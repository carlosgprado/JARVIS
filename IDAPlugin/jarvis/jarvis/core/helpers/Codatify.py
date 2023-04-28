# IDA plugin that converts all data in data segments to defined data types, and all data in code segments to code.
#
# Use by going to Options->Define data and code.
#
# Craig Heffner
# Tactical Network Solutions

import idc
import idaapi
import idautils

class Codatify(object):

    CODE = 2
    DATA = 3
    SEARCH_DEPTH = 25

    def __init__(self, say = None):
        self.say = say
        if self.get_start_ea(self.DATA) == idc.BADADDR:
            if idc.ask_yn(0, "There are no data segments defined! This probably won't end well. Continue?") != 1:
                raise Exception("Action cancelled by user.")

    # Get the start of the specified segment type (2 == code, 3 == data)
    def get_start_ea(self, attr):
        ea = idc.BADADDR
        seg = idc.get_first_seg()

        while seg != idc.BADADDR:
            if idc.get_segm_attr(seg, idc.SEGATTR_TYPE) == attr:
                ea = seg
                break
            else:
                seg = idc.get_next_seg(seg)

        return ea

    # Creates ASCII strings
    def stringify(self):
        n = 0
        ea = self.get_start_ea(self.DATA)

        if ea == idc.BADADDR:
            ea = idc.get_first_seg()

        self.say("Looking for possible strings starting at: %s:0x%X..." % (idc.get_segm_name(ea), ea))

        for s in idautils.Strings():
            if s.ea > ea:
                if not idc.is_strlit(idc.get_full_flags(s.ea)) and idc.MakeStr(s.ea, idc.BADADDR):
                    n += 1

        self.say("created %d new ASCII strings" % n)

    # Converts remaining data into DWORDS.
    def datify(self):
        ea = self.get_start_ea(self.DATA)
        if ea == idc.BADADDR:
            ea = idc.get_first_seg()

        self.say("Converting remaining data to DWORDs...",)

        while ea != idc.BADADDR:
            flags = idc.get_full_flags(ea)

            if (idc.isUnknown(flags) or idc.isByte(flags)) and ((ea % 4) == 0):
                idc.MakeDword(ea)
                idc.OpOff(ea, 0, 0)

            ea = idc.next_addr(ea)

        self.say("done.")

        self._fix_data_offsets()

    def pointify(self):
        counter = 0

        self.say("Renaming pointers...",)

        for (name_ea, name) in idautils.Names():
            for xref in idautils.XrefsTo(name_ea):
                xref_name = idc.get_name(xref.frm)
                if xref_name and xref_name.startswith("off_"):
                    i = 0
                    new_name = name + "_ptr"
                    while idc.get_name_ea_simple(new_name) != idc.BADADDR:
                        new_name = name + "_ptr%d" % i
                        i += 1

                    if idc.MakeName(xref.frm, new_name):
                        counter += 1
                    #else:
                    #    self.say("Failed to create name '%s'!" % new_name)

        self.say("renamed %d pointers" % counter)

    def _fix_data_offsets(self):
        ea = 0
        count = 0

        self.say("Fixing unresolved offset xrefs...",)

        while ea != idaapi.BADADDR:
            (ea, n) = idaapi.find_notype(ea, idaapi.SEARCH_DOWN)
            cmd = insn_t()
            if idaapi.decode_insn(cmd, ea) != 0:
                for i in range(0, len(cmd.ops)):
                    op = cmd.ops[i]
                    if op.type == idaapi.o_imm and idaapi.getseg(op.value):
                        idaapi.add_dref(ea, op.value, (idaapi.dr_O | idaapi.XREF_USER))
                        count += 1

        self.say("created %d new data xrefs" % count)

    # Creates functions and code blocks
    def codeify(self, ea=idc.BADADDR):
        func_count = 0
        code_count = 0

        if ea == idc.BADADDR:
            ea = self.get_start_ea(self.CODE)
            if ea == idc.BADADDR:
                ea = idc.get_first_seg()

        self.say("\nLooking for undefined code starting at: %s:0x%X" % (idc.get_segm_name(ea), ea))

        while ea != idc.BADADDR:
            try:
                if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == self.CODE:
                    if idc.get_func_name(ea) != '':
                        ea = idc.FindFuncEnd(ea)
                        continue
                    else:
                        if idc.MakeFunction(ea):
                            func_count += 1
                        elif idc.MakeCode(ea):
                            code_count += 1
            except:
                pass

            ea = idc.next_addr(ea)

        self.say("Created %d new functions and %d new code blocks\n" % (func_count, code_count))
