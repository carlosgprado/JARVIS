#!/usr/bin/python
#
# Name: Misc.py
# Description: Auxiliary functions which can not be stored anywhere else
#

from idc import *
from idaapi import *
from idautils import *

from collections import defaultdict
import traceback
import re
import math


#################################################################
def to_str(unicode_or_string):
    """
    Efficient Python is a cool book :)
    :param unicode_or_string: exactly that
    :return: an instance of str
    """
    if isinstance(unicode_or_string, str):
        value = unicode_or_string.encode('utf-8')

    else:
        value = unicode_or_string

    return value


#################################################################
def pyside_to_ida_color(s):
    """
    Converts PySide color ('#RRGGBB') to
    IDA color (0xBBGGRR)
    """
    pc = int(s[1:], 16)

    r = (pc & 0xff0000) >> 16
    g = (pc & 0xff00) >> 8
    b = pc & 0xff

    # I could optimize this but it is more legible this way :)
    ic = (b << 16) | (g << 8) | r

    return ic


#################################################################
def module_boundaries():
    """
    Convenience function.
    Returns min and max addresses
    :return: boundaries
    """

    return (inf_get_min_ea(), inf_get_max_ea())


#################################################################
def function_boundaries(ea = None):
    """
    Convenience function
    If not ea is given, current function is used
    :returns: boundaries or None
    """
    if not ea:
        ea = here()

    f = get_func(ea)

    if not f:
        # Probably called outside a function
        return (None, None)

    else:
        return (f.start_ea, f.end_ea)


#################################################################
def iter_disasm():
    """
    Convenient iterator.
    Returns all disassembly within a function
    """

    for ins in FuncItems(get_screen_ea()):
        yield (ins, GetDisasm(ins))


#################################################################
def is_external_jmp(ins_ea):
    """
    True for JMPs between functions.
    NN_JMP (86): jmp sub_xxx (0xE9 + offset) or jmp loc_xxx (0xE9 + offset)
    NN_JMPNI (88): jmp __imp_Writefile (0xFF25 + address in .idata)
    These appear unfortunately in loops as well:
    (jmp ds:dwordxxx[eax*4] or alike)K
    """
    # TODO: Check if this is accurate (unit tests? :))

    cmd = insn_t()	
    decode_insn(cmd, ins_ea)

    if cmd.itype == NN_jmpni:
        target = get_operand_value(ins_ea, 0)
        # TODO: This is valid for PE format only
        # Is this a thunk?
        if get_segm_name(target) == '.idata':
            return True

    if cmd.itype == NN_jmp:
        # HACK: get_operand_value returns the target
        # address, not the offset (as I would expect)
        target = get_operand_value(ins_ea, 0)
        (s, e) = function_boundaries(ins_ea)

        if target < s or target > e:
            # Not within the current function
            return True

    return False


#################################################################
def jump_to_address(addr):
    """
    Convenience function
    """
    try:
        idc.jumpto(addr)

    except:
        print(traceback.format_exc())


#################################################################
def get_function_name(addr=None):
    """
    Convenience function.
    Without parameters returns
    the name of the current function.
    """
    if not addr:
        addr = get_screen_ea()

    name = get_func_name(addr)

    # get_func_name returns empty string
    # on failure, hex(addr) is better than nothing
    if not name:
        name = "%x" % addr

    return name


#################################################################
def name_to_address(name):
    """
    Convenience function.
    Return function StartEA or 0xFFFFFFFF
    """
    return get_name_ea_simple(name)


#################################################################
def get_platform():
    """
    The platform this binary was built for
    Raises an exception if not supported
    :return: string
    """
    pl_dict = {0: '386', 8: 'JAVA',
               12: 'MIPS', 13: 'ARM',
               15: 'PPC', 19: 'NET'
               }

    p = ph.id  # magic!

    if p in pl_dict:
        return pl_dict[p]

    else:
        raise Exception('Architecture NOT supported')


#################################################################
def is_64bit():
    """
    Convenience wrapper :)
    Is the IDB in front of me from a 64 or 32 bits binary?
    """
    return idc.__EA64__


#################################################################
def get_code_section_address():
    """
    Name says it all :)
    """
    for seg_ea in Segments():
        if get_segm_name(seg_ea) == '.text':
            return seg_ea

    return None


#################################################################
def paint_basic_blocks(addr, color = None):
    """
    Paint the whole basic block(s) with the specified color
    NOTE: don't mind the cheap polymorphism hack :)
    """
    # TODO: This algorithm sucks balls.
    # TODO: maybe move the alg. finding the bb somewhere else?

    if type(addr) == int:
        addr_l = [addr]

    elif type(addr) == list:
        addr_l = addr

    else:
        addr_l = []

    # Calculate the FlowChart (once outside of the loop)
    # This generator is needed to get the bb boundaries
    try:
        a_0 = addr_l[0]
    except IndexError:
        return

    f = get_func(a_0)
    if not f:
        return

    fc = FlowChart(f, None, FC_PREDS)

    for addr in addr_l:
        for bb in fc:
            # Remember that bb.end_ea is bb.start_ea of the next one!
            if addr >= bb.start_ea and addr < bb.end_ea:
                # This is the one
                for ins in Heads(bb.start_ea, bb.end_ea):
                    set_color(ins, CIC_ITEM, color)


#################################################################
def set_ins_color(addr, color=0x2020c0):
    """
    A simple wrapper.
    It colors a single instruction.
    """
    set_color(addr, CIC_ITEM, color)


#################################################################
# Lots of functions have to do something with imports
# It is easier to pack everything in a class
#################################################################
class importManager():
    def __init__(self):
        """
        All methods will be using this dictionary
        """
        self.import_dict = {}
        self._enum_all_imports()

    def find_import_callers(self, regexp):
        """
        Finds interesting imported functions and the nodes that call them.
        Very handy in locating user inputs.

        @attention: There are imports called through a thunk and directly.
        @rtype: Dictionary (of lists)
        @return: Dictionary containing *the address of the functions*
                 calling the imports,
                 {fn_call_ea: [idata1_ea, idata2_ea, ...], ...}
        """
        # TODO: IIRC this needs some review

        importCallers = defaultdict(list)
        importPattern = re.compile(regexp, re.IGNORECASE)

        for imp_name, imp_ea in self.import_dict.items():

            # This dict has the *IAT names*
            # i.e. __imp_ReadFile, within the .idata section
            if importPattern.match(imp_name):

                for import_caller in XrefsTo(imp_ea, 1):
                    import_caller_addr = import_caller.frm
                    import_caller_fn = get_func(import_caller_addr)

                    if not import_caller_fn:
                        continue

                    # Check if caller is a THUNK
                    if import_caller_fn.flags & FUNC_THUNK:
                        # It is a thunk: Not very interesting.
                        # Who is calling this thunk?
                        for thunk_caller in XrefsTo(import_caller_addr, 1):
                            thunk_caller_fn = get_func(thunk_caller.frm)

                            if not thunk_caller_fn:
                                continue

                            import_caller_ea = thunk_caller_fn.start_ea
                            # Remove nasty duplicates
                            if imp_ea not in importCallers[import_caller_ea]:
                                importCallers[import_caller_ea].append(imp_ea)

                    else:
                        # It is NOT a thunk, no need for recursion
                        import_caller_ea = import_caller_fn.start_ea
                        # Remove nasty duplicates
                        if imp_ea not in importCallers[import_caller_ea]:
                            importCallers[import_caller_ea].append(imp_ea)

        return importCallers

    def _enum_all_imports(self):
        """
        Useful afterwards for resolving addresses to imports.
        This code has been taken shamelessly from the "ex_imports.py" example.

        @rtype: dictionary
        @return: dictionary containing import name & address {"name" : imp_ea}
        """
        print("= [*] Populating imports dictionary...")

        nimps = get_import_module_qty()  # How many modules imported?

        for i in range(0, nimps):
            name = get_import_module_name(i)
            if not name:
                print("[x] Could not get import module name for #%d" % i)
                continue

            # The import_dict dictionary will be filled
            # through this callback function (_imp_cb)
            enum_import_names(i, self._imp_cb)

        return self.import_dict

    def _imp_cb(self, ea, name, ord):
        """
        Used by _enum_all_imports.
        Callback function used by idaapi.enum_import_names()

        @return: True
        """

        if not name:
            self.import_dict[ord] = ea

        else:
            self.import_dict[name] = ea

        return True

    def _find_import_name(self, iaddr):
        """
        Translates addresses to import names through a dictionary lookup.

        @type iaddr: address
        @param iaddr: Address of import

        @return: name (if successful) or same argument (on failure)
        """

        for k, v in self.import_dict.items():
            if v == iaddr:
                name = k
                break

        if name:
            return name

        else:
            return iaddr


#################################################################
# Shannon's entropy is a must :)
#################################################################
def entropy(s):
    """
    Shannon's definition:
    sum{ x, -p(x) * log2(p(x)) }
    """
    H = 0.0

    for c in range(256):
        if s.count(chr(c)) > 0:
            H += -1.0 * p(c, s) * math.log(p(c, s), 2)

    return H


def p(c, s):
    """
    Frequency of c in s
    """
    return s.count(chr(c)) / (len(s) * 1.0)


#################################################################
# Some useful constants come here to avoid
# cluttering the "main" source code
#################################################################

banned_functions = [
    "strcpy", "strcpya", "strcpyw", "wcscpy", "_tcscpy", "_mbscpy", "strcpy", "strcpya", "strcpyw", "lstrcpy",
    "lstrcpya", "lstrcpyw", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy",
    "strcpyn", "strcpyna", "strcpynw", "strncpy", "strcpyna", "strncpya", "strncpyw", "lstrcpyn", "lstrcpyna",
    "lstrcpynw", "strcat", "strcata", "strcatw", "wcscat", "_tcscat", "_mbscat", "strcat", "strcata", "strcatw",
    "lstrcat", "lstrcata", "lstrcatw", "strcatbuff", "strcatbuffa", "strcatbuffw", "strcatchainw", "_tccat", "_mbccat",
    "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "strcatn", "strcatna", "strcatnw", "strncat",
    "strncata", "strncatw", "lstrncat", "lstrcatna", "lstrcatnw", "lstrcatn", "sprintfw", "sprintfa", "wsprintf",
    "wsprintfw", "wsprintfa", "sprintf", "swprintf", "_stprintf", "wvsprintf", "wvsprintfa", "wvsprintfw", "vsprintf",
    "_vstprintf", "vswprintf", "wvsprintf", "wvsprintfa", "wvsprintfw", "vsprintf", "_vstprintf", "vswprintf",
    "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "strcpyn", "strcpyna", "strcpynw", "strncpy", "strcpyna",
    "strncpya", "strncpyw", "lstrcpyn", "lstrcpyna", "lstrcpynw", "_fstrncpy", "strncat", "wcsncat", "_tcsncat",
    "_mbsncat", "_mbsnbcat", "strcatn", "strcatna", "strcatnw", "strncat", "strncata", "strncatw", "lstrncat",
    "lstrcatna", "lstrcatnw", "lstrcatn", "_fstrncat", "strtok", "_tcstok", "wcstok", "_mbstok", "makepath",
    "_tmakepath", "_makepath", "_wmakepath", "_splitpath", "_tsplitpath", "_wsplitpath", "scanf", "wscanf", "_tscanf",
    "sscanf", "swscanf", "_stscanf", "snscanf", "snwscanf", "_sntscanf", "_itoa", "_itow", "_i64toa", "_i64tow",
    "_ui64toa", "_ui64tot", "_ui64tow", "_ultoa", "_ultot", "_ultow", "gets", "_getts", "_gettws", "chartooem",
    "chartooema", "chartooemw", "oemtochar", "oemtochara", "oemtocharw", "chartooembuffa", "chartooembuffw", "alloca",
    "_alloca", "strlen", "wcslen", "_mbslen", "_mbstrlen", "lstrlen", "rtlcopymemory", "copymemory", "wmemcpy", "memcpy"
]
