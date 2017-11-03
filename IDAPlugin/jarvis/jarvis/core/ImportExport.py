#!/usr/bin/python
#
# Name: ImportExport.py
#
# Description: Functions used to share information with other programs.
#              This allows to add external information to our analysis as well.
#


from idc import *
from idaapi import *
from idautils import *

import json
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
            filename = AskFile(1, "function_bytes.txt",
                               "File to save the code?")
            code_s = ''.join([
                "%02x" % get_byte(x) for x in xrange(begin, end)])
            with open(filename, 'w') as f:
                f.write(code_s)

            return True

        except:
            return False


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
        with open(filename, 'r') as f:
            j_obj = json.loads(f.read())

        for m in j_obj['modules']:
            # TODO: Get the loaded binary name!!!
            if m['name'] == GetInputFilePath():
                return m['begin']

        return None

    def file_parser(self, filename):
        """
        Read trace addresses from a JSON file
        Format:
        "calls" : [{"tid": 0, "u": 0xcafe, "v": 0xbabe, "indirect": true}, ...]
        @return: d[thread_id] = [(u_ea, v_ea), ...]
        """
        print "[*] Parsing file:", filename
        trace_d = defaultdict(list)

        with open(filename, 'r') as f:
            j_obj = json.loads(f.read())

        for c in j_obj['calls']:
            u_ea = c['u']
            v_ea = c['v']
            thread_id = c['tid']

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
        filename = AskFile(1, "*.json", "File to import addresses from?")

        # Rebase
        image_base = self.get_image_base(filename)
        if not image_base:
            print 'import_data() - Could not get image base from trace'
            raise 'ImportFailure'

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

    def import_dynamic_calls(self):
        """
        Gets information from a PIN tool
        @return: dictionary
        """
        dyn_calls_dict = defaultdict(set)

        filename = AskFile(1, "*.json", "File to import information from?")

        try:
            with open(filename, 'r') as f:
                j_obj = json.loads(f.read())

                # Need to rebase?
                image_base = self.get_image_base(filename)
                ida_base = get_imagebase()  # idaapi
                delta = image_base - ida_base

                if delta:
                    # IDA would go ahead with the rebasing process
                    # even if the delta is zero. This avoids it.
                    rebase_program(delta, MSF_FIXONCE)

                for c in j_obj['calls']:
                    if not c['indirect']:
                        continue

                    u_ea = c['u']
                    v_ea = c['v']

                    # Filter dynamic calls related to system DLLs (ghetto)
                    if u_ea > 0x00800000:
                        continue

                    # set: unique entries
                    dyn_calls_dict[u_ea].add(v_ea)
        except Exception as e:
            # We just return silently
            return

        # Add these calls to the IDB
        for frm, to_list in dyn_calls_dict.iteritems():
            for to in to_list:
                AddCodeXref(frm, to, fl_CN)
                # TODO: Display the imported info in a table format?
                print "Added CodeXrefs from {} to {}".format(hex(frm), hex(to))

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
