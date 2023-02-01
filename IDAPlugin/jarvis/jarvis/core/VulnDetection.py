#!/usr/bin/python
#
# Name: VulnDetection.py
# Description: It eases the process of automatic vulnerability detection.
#
# TODO: UINT overflow / undeflow
# TODO: Improve algorithm for signed issues
#

from idc import *
from idaapi import *
from idautils import *

import jarvis.core.helpers.Misc as misc
from jarvis.core.helpers.IntegerIssues import IntegerIssues


#############################################################################
class VulnDetection():

    def __init__(self):

        print("= Loading vulnerability detection module...")

        # Since this is pretty demanded information
        # let's calculate it here
        self.im = misc.importManager()
        self.ii = IntegerIssues()
        self.cache = VulnDetectionCache()

    def find_string_format(self):
        """
        First attempt to find possible string
        format vulnerabilities
        """
        # TODO: actually write some code here :)

        for n in self.im.import_dict.keys():
            if n.lower() in dangerous_funcs:
                # This is an "interesting" import
                pass

    def find_dangerous_function_names(self):
        """
        Search for functiona names like:
        _memcpy, memcpy_0 or similar
        @return: list of strings
        """
        dang_funcnames = []

        for f_ea in Functions():
            f_name = get_func_name(f_ea)

            for dang_name in misc.banned_functions:
                # skip those pesky secure functions
                if dang_name in f_name and f_name[-2:] != '_s':
                        dang_funcnames.append(f_name)
                        continue

        return dang_funcnames

    def find_banned_functions(self, deep_search = True):
        """
        Functions banned by Microsoft.
        Included functions with suspicious names
        (maybe inlined and detected by IDA)
        """
        if not self.cache.last_deep_search_param or \
                self.cache.last_deep_search_param != deep_search:
            # This is the first time we hit this
            # or the deep_search param has changed since
            # the last call, either way calculate from scratch

            # Calculate the cache for the first time
            self.cache.banned_refs = dict()

            for n in self.im.import_dict.keys():
                if n.lower() in misc.banned_functions:
                    func_addr = get_name_ea_simple(n)
                    if func_addr == BADADDR:
                        continue

                    # get all (code) references to the function
                    # thus ignoring things like: "mov edi, ds:wsprintfA"
                    self.cache.banned_refs[n] = list(CodeRefsTo(func_addr, True))

            if deep_search:
                # Add to the list the (possibly) inlined functions
                for m in self.find_dangerous_function_names():
                    func_addr = get_name_ea_simple(m)
                    self.cache.banned_refs[m] = list(CodeRefsTo(func_addr, True))

        return self.cache.banned_refs


##############################################################################
class VulnDetectionCache():

    def __init__(self):
        self.last_deep_search_param = None
        self.banned_refs = None
