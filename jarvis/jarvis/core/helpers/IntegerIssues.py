#!/usr/bin/python
#
# Name: IntegerIssues.py
# Description: Code related to finding signed issues (conversion, comparison, etc.)
#              Part of Jarvis IDA Pro Plugin
#
# TODO: x86_64 support, semantic checks, etc.
#

from idc import *
from idaapi import *
from idautils import *

from jarvis.core.helpers.Graphing import BlockGraph
import jarvis.core.helpers.Misc as misc


####################################################################################
class IntegerIssues():

    def __init__(self):

        # TODO: expand the list of dangerous functions
        self.dangerous_calls = set([])
        self.dangerous_funcs_dict = dict()
        self.dangerous_patterns = {
                              'snprintf': 3,
                              'strncpy': 3,
                              'memcpy': 3,
                              'memset': 3,
                              'strncat': 3,
                              'recvfrom': 5,
                              'bcopy': 3,
                              'malloc': 1,
                              'wcscpy': 2,
                              'wcsncpy': 3,
                              }


    def called_dangerous_funcs(self):
        """
        Fills the dictionary of dangerous functions
        present in the binary. Mark their references.
        """

        # Let's fill the dangerous funcs dict based only on name
        # TODO: maybe do something with FLIRT signatures or alike?

        for func_ea in Functions():
            func_name = GetFunctionName(func_ea)
            for pattern, dang_arg_idx in self.dangerous_patterns.iteritems():
                if pattern in func_name:
                    # NOTE this is very relaxed. Names like
                    # memset_0 or __malloc will fit as well
                    self.dangerous_funcs_dict[func_name] = (func_ea, dang_arg_idx)

                    # Find all code references to the dangerous
                    # function and mark them
                    for ref in XrefsTo(func_ea, 0):
                        self.dangerous_calls.add(ref.frm)
                        # Color the function call *RED*
                        SetColor(ref.frm, CIC_ITEM, 0x2020c0)

                    break


    def get_dangerous_args(self, ea):
        """
        Find the dangerous function arguments
        Ex. "call strncpy" find the third push,
        which should correspond to the size argument
        @returns: list of arguments (may be empty)
        """

        # TODO: x86 only at the moment, x64 at least
        # TODO: the algo as a whole is flaky...
        # which paths are being considered?
        if misc.is_64bit():
            raise NotImplementedError

        prev_addr = ea
        dang_args = []
        dang_name = GetOpnd(ea, 0)
        dang_arg_idx = 0

        for pat, arg_idx in self.dangerous_patterns.iteritems():
            if pat in dang_name:
                dang_arg_idx = arg_idx

        while dang_arg_idx > 0:
            pi = DecodePreviousInstruction(prev_addr)

            # DecodePreviousInstruction returns None if we try
            # to decode past the beginning of the function
            if not pi:
                return []

            if pi.get_canon_mnem() == 'push':
                dang_arg_idx -= 1
                push_op = GetOpnd(pi.ea, 0)
                dang_args.append(push_op)

            prev_addr = pi.ea

        return dang_args


    def get_signed_cmp(self, dangerous_ea):
        """
        Find the signed compare before the dangerous call
        @returns: tuple with the comparison operands or None
        """

        signed_jmp = ['jg', 'jge', 'jng', 'jnge', 'jl', 'jle', 'jnl', 'jnle']

        try:
            bg = BlockGraph(dangerous_ea)

        except:
            # Probably the address was not related to a function
            # or to something IDA could NOT identify as a function
            return None

        for pred in bg.get_block_preds(dangerous_ea):
            # Final instruction of the predecessor
            # Must be the last instruction per definition
            jumpi = bg.get_block_tail_ins(pred.startEA)

            if not jumpi:
                continue

            if jumpi.get_canon_mnem() in signed_jmp:
                # TODO: Heuristic!
                # Usually before a signed jump there is
                # the corresponding comparison
                cmpi = DecodePreviousInstruction(jumpi.ea)

                if GetMnem(cmpi.ea) == "cmp":
                    return (GetOpnd(cmpi.ea, 0), GetOpnd(cmpi.ea, 1))

                elif GetMnem(cmpi.ea) == "test":
                    # Eliminate this case: test eax, eax
                    if GetOpnd(cmpi.ea, 0) != GetOpnd(cmpi.ea, 1):
                        return (GetOpnd(cmpi.ea, 0), GetOpnd(cmpi.ea, 1))

        return None


    def search_integer_issues(self):
        """
        Searches the *whole* binary for integer issues, like signed
        integer comparison, etc.
        @returns: list of addresses (suspicious instructions to check)
        """

        suspicious_ins_list = []

        # Generates a list of functions calling dangerous ones.
        self.called_dangerous_funcs()

        for dang_call_ea in self.dangerous_calls:
            # Get a list of arguments pushed before the call
            try:
                dang_args = self.get_dangerous_args(dang_call_ea)
                if not dang_args:
                    continue

                last_arg = dang_args[-1]

            except NotImplementedError:
                # x86 only, for now
                raise

            # Get the (signed) cmp before the signed jump
            cmp_args = self.get_signed_cmp(dang_call_ea)

            # Check whether the args were used in a comparison
            if cmp_args:
                if cmp_args[0] == last_arg:
                    # This is a nice finding
                    suspicious_ins_list.append(dang_call_ea)

        return suspicious_ins_list

