#!/usr/bin/python
#
# Name: ImportExport.py
#
# Description: Implements functions used to share information with other programs.
#              This allows to add external information to our analysis as well.
#


from idc import *
from idaapi import *
from idautils import *

from collections import defaultdict


import jarvis.core.helpers.Misc as misc
import jarvis.core.helpers.Graphing as graphing


class ImportExport():

    def __init__(self):

        print "= Loading import / export module..."

        self.ti = TraceImporter()


    def export_current_function(self):
        """
        Exports the current function code, ascii hex encoded
        This is useful to import into tools like miasm and alike
        """
        # TODO: Reading one byte at a time must be EXTREMELY INEFFICIENT!!! o.O

        begin, end = misc.function_boundaries()

        try:
            filename = AskFile(1, "function_bytes.txt", "File to save the code?")
            code_s = ''.join(["%02x" % get_byte(x) for x in xrange(begin, end)])
            with open(filename, 'w') as f:
                f.write(code_s)

            return True

        except:
            return False


    def import_dynamic_calls(self):
        """
        Gets information from a PIN tool
        @return: dictionary
        """
        dyn_calls_dict = defaultdict(set)

        filename = AskFile(1, "*.txt", "File to import information from?")

        with open(filename, 'r') as f:
            lines = f.readlines()
            lines_i = [x.strip() for x in lines if x.startswith('[I]')]

            # Need to rebase?
            module_bases = [x.split('\t')[1] for x in lines if 'Module base' in x]
            image_base = int(module_bases[0].strip(), 16)
            ida_base = get_imagebase()  # idaapi
            delta = image_base - ida_base

            if delta:
                # IDA would go ahead with the rebasing process
                # even if the delta is zero. This avoids it.
                rebase_program(delta, MSF_FIXONCE)

            call_str = ' -> '

            for line in lines_i:

                # Sanity check
                if not '[T:' in line:
                    continue

                a = line.split(']')[-1]
    
                eip, target = map(lambda x: int(x, 16), a.split(call_str))
                # Filter dynamic calls related to system DLLs (ghetto)
                if eip > 0x00800000:
                    continue

                # set: unique entries
                dyn_calls_dict[eip].add(target)

        # Add these calls to the IDB
        for frm, to_list in dyn_calls_dict.iteritems():
            for to in to_list:
                AddCodeXref(frm, to, fl_CN)
                # TODO: Display the imported info in a table format?
                print "Added CodeXrefs from {} to {}".format(hex(frm), hex(to))



class TraceImporter():

    def __init__(self):
        """
        Contains all the machinery used to import data
        from a PinTool trace
        """
        print "= Loading TraceImporter..."
        self.cache = TraceImporterCache()


    def get_image_base(self, filename):
        """
        Returns the recorded image base
        at the time of execution (for rebasing in IDA)
        """
        trace_s = open(filename, 'r').readlines()
        module_bases = [x.split('\t')[1] for x in trace_s if 'Module base' in x]
        image_base = int(module_bases[0].strip(), 16)

        return image_base


    def file_parser(self, filename):
        """
        Read trace addresses (only basic blocks)
        Format: [T:0] 0xcafe -> 0xbabe
        @return: d[thread_id] = [(u_ea, v_ea), ...]
        """

        print "[*] Parsing file:", filename
        trace_d = defaultdict(list)
        call_str = ' -> '

        trace_s = open(filename, 'r').readlines()
        trace_list = [line for line in trace_s if call_str in line]

        for x in trace_list:
            x = x.strip()
            # Sanity check
            if not '[T:' in x:
                continue

            # Dynamic call resolution start with '[I]'
            if x.startswith('[I]'):
                x = x.split('[I]')[-1].strip()
            t, a = x.split(']')

            u_ea, v_ea = map(lambda x: int(x, 16), a.split(call_str))
            thread_id = int(t.split(':')[-1])

            # FIXME: This excludes the items from the file
            # It would be better to filter at trace time
            if u_ea > MaxEA() or v_ea > MaxEA():
                continue

            trace_d[thread_id].append((u_ea, v_ea))

        # Cache this for later use
        self.cache.trace_d = trace_d

        return trace_d


    def import_data(self, bb_color = 0x581414):
        """
        Pretty straightforward, isn't it? ;)
        @return: dictionary d[tid] = [bb_ea, ...]
        """
        filename = AskFile(1, "*.*", "File to import addresses from?")

        # Rebase
        image_base = self.get_image_base(filename)
        ida_base = get_imagebase()  # idaapi
        delta = image_base - ida_base

        if delta:
            # IDA would go ahead with the rebasing process
            # even if the delta is zero. This avoids it.
            rebase_program(delta, MSF_FIXONCE)

        # Parse basic blocks from file
        trace_dict = self.file_parser(filename)

        for addr_list in trace_dict.values():
            for _, v_ea in addr_list:
                misc.paint_basic_blocks(v_ea, bb_color)

        return trace_dict


    def export_to_graphml(self):
        """
        GraphML is nice. Display with yed and enjoy.
        """
        filename = AskFile(1, "*.graphml", "File to export to?")

        if not filename:
            # For example, file dialog was closed
            print 'Error getting filename'
            return None

        if self.cache.trace_d:
            # Already populated
            trace_d = self.cache.trace_d

        else:
            print '[!] Could not find trace dictionary on cache'
            return None

        # TODO: working with tid 0 for now
        # Maybe just generate several filename_N.graphml?
        t0_list = trace_d[0]
        edge_list = [map(lambda x: GetFunctionName(x), e) for e in t0_list]

        return graphing.write_to_graphml(edge_list, filename)



##################################################################
class TraceImporterCache():
    """
    Cache the data imported from the PIN Trace.
    It will be used by the export to GraphML, for example
    """
    def __init__(self):
        self.trace_d = dict()

