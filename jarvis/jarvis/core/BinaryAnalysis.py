#!/usr/bin/python
#
# Name: BinaryAnalysis.py
# Description: Several functions assisting in reverse engineering tasks
#              not directly related to security.
#

from idc import *
from idaapi import *
from idautils import *

import itertools  # for islice()
from collections import defaultdict

import jarvis.core.helpers.Misc as misc
import jarvis.core.helpers.Graphing as graphing
from jarvis.Config import JConfig


#################################################################
class BinaryAnalysis():

    def __init__(self):
        """
        A bunch of more or less useful binary analysis
        routines. Not necessarily related to security stuff.
        """
        self.name = "BinaryAnalysis"
        self.im = misc.importManager()
        self.cache = BinaryAnalysisCache()
        self.config = JConfig()

        print "= Loading binary analysis module..."

    def comments_in_function(self):
        """
        Searches the current function for IDA generated annotations
        Useful when dealing with large functions doing lots of logging
        @return: a list of tuples [(addr, comment)]
        """
        comments = []

        for addr, dis in misc.iter_disasm():
            comm = Comment(addr)
            # Comment returns None if no comment
            if comm:
                comments.append((addr, comm))

        return comments

    def calls_in_function(self, unique = True):
        """
        Find calls within current function
        Execution transfer like jmp sub_xxx included
        @return: a list of tuples [(addr, dis)]
        """

        callees = []

        for addr, dis in misc.iter_disasm():
            if is_call_insn(addr) or misc.is_external_jmp(addr):
                if dis not in callees:
                    callees.append((addr, dis))

        return callees

    def calculate_strings_list(self):
        """
        It finds all strings within a binary
        @return: list of tuples [(s_ea, string), ...]
        """
        if not self.cache.string_list:
            # acts if string_list is not cached (initially)
            s = Strings(False)
            s.setup(strtypes = Strings.STR_UNICODE | Strings.STR_C)

            self.cache.string_list = []

            for v in s:
                try:
                    self.cache.string_list.append((v.ea, unicode(v)))

                except:
                    print "Error processing string at %x" % v.ea

    def get_string_references(self):
        """
        Get all references to strings within the current function
        @return: list of tuples [(xref addr, s), ...]
        """
        f = get_func(ScreenEA())
        if not f:
            # get_func returned None
            print '[x] This does not look like a function...'
            return []

        start = f.startEA
        end = f.endEA

        s_refs = []

        # TODO: This algorithm can be improved :)
        # For now I will make do
        for s_ea, s in self.cache.string_list:
            # Calculate xrefs
            for ref in XrefsTo(s_ea, True):
                ref_addr = ref.frm
                # Within current function?
                if ref_addr >= start and ref_addr <= end:
                    s_refs.append((ref_addr, s))

        return s_refs

    def most_referenced_functions(self, number = 10):
        """
        Identifying these is an important first step
        @return: tuple list [ (f_ea, (nr_of_refs, ref_name)), ... ]
        """
        if self.cache.top_ref_list:
            return self.cache.top_ref_list

        else:
            referenceDict = dict()

            for funcAddr in Functions():
                # stackoverflow ;)
                nr_of_refs = sum(1 for e in XrefsTo(funcAddr, True))
                ref_name = GetFunctionName(funcAddr)
                referenceDict[funcAddr] = (nr_of_refs, ref_name)

            # Let's order this stuff nicely
            sd = sorted(referenceDict.iteritems(), reverse = True,
                        key = lambda (k, v): (v[0], k))
            top_ref_list = list(itertools.islice(sd, number))

            # Cache it for later use
            self.cache.top_ref_list = top_ref_list

            return top_ref_list

    def xor_patcher(self):
        """
        The name says it all
        """

        start = SelStart()
        if start == BADADDR:
            print "Select the code to XOR"
            return False

        end = SelEnd()
        if end == BADADDR:
            print "Select the code to XOR"
            return False

        # Ask for the byte
        key = AskLong(0, "Number to XOR selected area with (one byte!)")
        if key == -1:
            print "Error"
            return False

        # This is the actual XORing routine. No magic here.
        position = start
        while position <= end:
            PatchByte(position, Byte(position) ^ key)
            position += 1

        print "Patched %d bytes [%08x - %08x]" % (end - start + 1, start, end)

    def find_imm_compares(self):
        """
        Find all immediate compares in the current function.
        Very useful when debugging parsers, for example.
        @return: list of tuples [(address, disassembly),...]
        """
        cmp_addr = []

        for addr, dis in misc.iter_disasm():
            if "cmp" in dis:
                if GetOpType(addr, 1) == o_imm:  # 5: immediate value
                    cmp_addr.append((addr, dis))

        return cmp_addr

    def locate_file_io(self):
        """
        Convenience function
        Finds interesting IO related *imports* and the functions calling them.
        Call with interactive = True to display a custom viewer ;)

        @rtype: Dictionary (of lists)
        @return: Dictionary of functions calling imported functions,
                 {fn_ea: [file_io1_ea, file_io2_ea, ...], ...}
        """

        # The meat and potatoes is the regexp
        regexp = ".*readf.*|.*write.*|.*openf.*|f.*print.*|.*fopen.*"
        callerDict = self.im.find_import_callers(regexp)

        return callerDict

    def locate_net_io(self):
        """
        Convenience function
        Finds interesting network related *imports* and functions calling them.
        Call with interactive = True to display a custom viewer ;)

        @rtype: Dictionary (of lists)
        @return: Dictionary containing functions calling imported functions,
                 {fn_ea: [net_io1_ea, net_io2_ea, ...], ...}
        """

        # The meat and potatoes is the regexp
        regexp = "recv|recvfrom|wsarecv.*"
        callerDict = self.im.find_import_callers(regexp)

        return callerDict

    def get_dword_compares(self):
        """
        Inspects the *whole* binary looking for comparisons between
        global dwords and immediate values. These usually contain error
        codes or alike and appear constantly through the code.
        """
        dword_dict = defaultdict(list)

        # TODO: This is too x86...
        for f_addr in Functions():
            for ins in FuncItems(f_addr):
                m = GetMnem(ins)
                if m == 'cmp' or m == 'test':
                    if GetOpType(ins, 1) == 5:  # o_imm: immediate value
                        if GetOpType(ins, 0) == 2:  # o_mem: memory ;)
                            op1, op2 = GetOpnd(ins, 0), GetOpnd(ins, 1)
                            if 'dword_' in op1:
                                # ex: cmp dword_xxx, 1000
                                # ex2: cmp cs:dword_xxx, 0
                                # Just unique values
                                if op2 not in dword_dict[op1]:
                                    dword_dict[op1].append((op2, ins))

        return dword_dict

    def get_all_functions(self):
        """
        It returns a list of all functions in a binary.
        This will not be cached since the names can change.
        @return: list of tuples [(f_ea, f_name), ...]
        """

        func_list = []

        for f_ea in Functions():
            f_name = GetFunctionName(f_ea)
            func_list.append((f_ea, f_name))

        return func_list

    def get_connect_graph(self, u, v):
        """
        Calculates a ConnectGraph from orig to dest
        """
        fg = graphing.FunctionGraph()

        co = self.config.connect_func_cutoff
        cg = fg.connect_graph(u, v, co)

        if cg == {}:
            return False

        else:
            return cg

    def show_connect_graph(self, cg = None):
        """
        Convenience method
        Displays a ConnectGraph from orig to dest
        """
        if cg:
            conn = graphing.ConnectGraph(cg)
            conn.Show()
            return True

        else:
            return False

    def input_to_function(self, ea = None):
        """
        Gets all functions calling IO (net & file) whose downgraph
        is connected to the specified function
        If none is specified, then use current function
        @returns: a list of f_ea's (io callers)
        """
        connected_input_list = []

        if not ea:
            # Called without arguments
            # Use current function
            ea = misc.function_boundaries()[0]

        io_list = self.locate_file_io().keys() + self.locate_net_io().keys()

        for caller_ea in io_list:
            cg = self.get_connect_graph(caller_ea, ea)
            if cg:
                connected_input_list.append(caller_ea)

        return connected_input_list

    def get_dangerous_functions(self):
        """
        Gets a list of functions calling
        dangerous ones
        @returns: a *set* of func_addr's
        """
        # TODO: use a centralized list for the dangerous functions?
        # TODO: this whole process must be O(mfg).
        bad_funcs = set([])

        dangerous_funcs = ["wcsncpy", "strcpy", "_strcpy", "_strcpy_0",
                           "strncpy", "_strncpy", "_strncpy_0",
                           "memmove", "memcpy", "_memcpy", "_memcpy_0"]

        # Loop from start to end within the current segment
        for func_name in dangerous_funcs:
            func_addr = LocByName(func_name)

            if func_addr == BADADDR:
                continue

            # find all code references to the function
            for ref in CodeRefsTo(func_addr, True):
                func_addr = misc.function_boundaries(ref)[0]
                bad_funcs.add(func_addr)

        return bad_funcs

    def get_all_dangerous_connections(self):
        """
        Get all connections between IO and dangerous
        functions. It is a necessary (but not sufficient)
        condition for a problem like memory corruption
        All code pieces were there already :)
        """
        conn_graphs = []
        dang_conns = []
        dang_funcs = self.get_dangerous_functions()

        if not dang_funcs:
            return []

        for df in dang_funcs:
            for io_caller in self.input_to_function(df):
                # [(u, v), ...]
                dang_conns.append((io_caller, df))

        # Calculate the connect graphs
        for tu in dang_conns:
            u, v = tu   # tuple unpacking
            cg = self.get_connect_graph(u, v)
            sh_path = graphing.cg_shortest_path(cg, u, v)

            if not sh_path:
                # Error. Skipping this one
                continue

            sh_path_len = len(sh_path) - 1  # by definition
            conn_graphs.append((u, v, sh_path_len))

        return conn_graphs

    def get_bb_connect_graph(self, co):
        """
        This is a thin wrapper.
        :param co:
        :return: generator of lists or None
        """
        bg = graphing.BlockGraph(here())
        paths = bg.find_connected_paths(co)

        if not paths:
            return None

        return paths


#################################################################
class BinaryAnalysisCache():
    """
    This 'data structure' is used to cache some not mutable values
    in order to avoid recalculating them over and over again.
    """
    def __init__(self):
        self.string_list = []
        self.top_ref_list = []
        self.bb_paths = []
