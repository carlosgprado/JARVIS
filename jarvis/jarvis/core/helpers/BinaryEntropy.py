#!/usr/bin/python
#
# Name: BinaryEntropy.py
# Description: Creates a nice (clickable) image
# of the binary's entropy
#


from idc import *
from idaapi import *
from idautils import *

from collections import defaultdict
from math import log
import struct

from Misc import entropy


class BinaryEntropy():
    """
    Calculates the entropy of the binary
    Useful in firmware analysis, for example.
    """

    def __init__(self):
        self.entropy_d = defaultdict(int)
        self.image_width = 400
        self.image_height = 400
        self.nr_cells = 100


    def get_block_size(self):
        """
        The block size is a function of
        the binary size
        :return: integer
        """
        bin_size = MaxEA() - MinEA()

        # NOTE: this is integer division (it rounds below)
        block_size = bin_size / self.nr_cells

        return block_size


    def calculate_entropy(self):
        """
        Calculates the entropy for the
        different blocks
        :return: None
        """
        block_size = self.get_block_size()

        for idx in xrange(self.nr_cells):
            block_start = idx * block_size
            # NOTE: GetManyBytes return a str object
            block_bytes = GetManyBytes(block_start, block_size)

            if not block_bytes:
                # Trying to read from blocks containing undefined data,
                # for example .idata section will return None
                # Even if some initialized data is present
                self.entropy_d[idx] = 0

            block_entropy = entropy(block_bytes)
            self.entropy_d[idx] = block_entropy


    def adjust_entropy_values(self):
        """
        Remember that for N-sized blocks the entropy
        peaks at log(N, 2)
        Our maximum if 32bits for RGB32 (0xFFRGB)
        :return:
        """
        RGB32_MAX = 0xFFFFFFFF
        entropy_max = log(self.get_block_size(), 2)

        # Correction: (e / e_max) * MAX

        for idx, e in self.entropy_d.iteritems():
            adjusted_entropy = (e / entropy_max) * RGB32_MAX
            # Remember, we need strings
            adjusted_entropy_s = struct.pack('>I', adjusted_entropy)
            self.entropy_d[idx] = adjusted_entropy_s

