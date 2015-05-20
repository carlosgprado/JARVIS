#!/usr/bin/python
#
# Name: Patching.py
# Description: routines regarding the use of IDA Pro
# as a binary editor (m1k3 I'm looking at you)
#


from idc import *
from idaapi import *
from idautils import *



class patched_bytes_visitor(object):
    """
    Visits all patched bytes and modifies
    the original data accordingly
    """
    def __init__(self):
        self.skip = 0
        self.patch = 0

        global patched_list
        patched_list = []

    def __call__(self, ea, fpos, o, v, cnt = ()):
        if fpos == -1:
            # Skipped byte
            self.skip += 1

        else:
            # This byte has been patched in IDA database
            self.patch += 1
            patched_list.append((fpos, o, v))

        return 0


def patch_binary():
    """
    Patches the original binary file
    @return: list of tuples [(fpos, o, v), ...] or None
    """

    # Get patched bytes
    v = patched_bytes_visitor()
    r = idaapi.visit_patched_bytes(0, idaapi.BADADDR, v)

    if r != 0:
        # Error. Possibly no patched bytes
        print "visit_patched_bytes() returned %d" % r
        return None

    filename = AskFile(1, "*.*", "Original file to patch?")

    if not filename:
        # For example, file dialog was closed
        return []

    with open(filename, 'rb') as f:
        original_file_data = bytearray(f.read())

    for fpos, o, p in patched_list:
        if original_file_data[fpos] == o:   # Sanity check
            original_file_data[fpos] = p

    # Write the patched file
    new_filename = filename + '.patched'
    with open(new_filename, 'wb') as f:
        # Not so original anymore :)
        f.write(original_file_data)

    return patched_list

