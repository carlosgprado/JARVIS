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

