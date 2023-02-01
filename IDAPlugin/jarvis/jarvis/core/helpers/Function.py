#!/usr/bin/python
#
# Name: Function.py
# Description: Misc routines related to function analysis
#

from idc import *
from idaapi import *
from idautils import *

from jarvis.core.helpers.Graphing import FunctionGraph


def get_number_of_args(call_addr):
    """
    Given the address of a CALL instruction, returns
    the number of parameters pushed to the stack
    before it. Useful for finding format string problems.
    """
    nr_pushes = 0
    nr_pops = 0

    # Sanity check
    if not is_call_insn(call_addr):
        raise Exception('Address does NOT belong to CALL instruction')

def backtrace_args_x86(ea, nr_args):
    """
    Find the dangerous function arguments
    Ex. "call strncpy" find the third push,
    which should correspond to the size argument
    @returns: list of tuples (op, ea) (may be empty)
    """

    if idc.__EA64__:
        raise Exception("Use 64 bit version!")

    #
    # x86 is a bit trickier.
    # We will track the pushes
    #
    prev_addr = ea
    arg_list = []
    while nr_args > 0:
        pi = DecodePreviousInstruction(prev_addr)

        # DecodePreviousInstruction returns None if we try
        # to decode past the beginning of the function
        if not pi:
            return []

        if pi.get_canon_mnem() == 'push':
            nr_args -= 1
            push_op = print_operand(pi.ea, 0)
            arg_list.append((push_op, pi.ea))

        prev_addr = pi.ea

    return arg_list
