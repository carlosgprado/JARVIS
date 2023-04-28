#!/usr/bin/python
#
# Name: BinaryEntropy.py
# Description: Creates a nice (clickable) image
# of the binary's entropy
#

from idc import *
from idaapi import *
from idautils import *

import struct
from collections import defaultdict
from math import log

from .Misc import entropy


class BinaryEntropy():
    """
    Calculates the current binary's entropy
    Useful in firmware analysis, for example.
    """

    def __init__(self):
        self.entropy_d = defaultdict(int)
        self.grid_size = 20
        self.nr_cells = self.grid_size ** 2
        self.block_size = self.get_block_size()

    def get_block_size(self):
        """
        The block size is a function of
        the binary size
        :return: integer
        """
        bin_size = inf_get_max_ea() - inf_get_min_ea()

        # NOTE: this is integer division (it rounds below)
        block_size = bin_size / self.nr_cells

        return block_size

    def calculate_entropy(self):
        """
        Calculates the entropy for the
        different blocks
        :return: None
        """
        block_size = self.block_size

        for idx in range(self.nr_cells):
            block_start = inf_get_min_ea() + (idx * block_size)
            # NOTE: GetManyBytes return a str object
            block_bytes = GetManyBytes(block_start, block_size)

            if not block_bytes:
                # Trying to read from blocks containing undefined data,
                # for example .idata section will return None
                # Even if some initialized data is present
                self.entropy_d[idx] = 1

            else:
                try:
                    block_entropy = entropy(block_bytes)
                    self.entropy_d[idx] = block_entropy

                except:
                    print("[!] Problem calculating block entropy (block %d)" % idx)
                    print("[!] Between %08x - %08x" % (block_start, block_start + block_size))
                    self.entropy_d[idx] = 3

    #################################################################
    # Auxiliary
    #################################################################
    def adjust_entropy_values(self):
        """
        Remember that for N-sized blocks the entropy
        peaks at log(N, 2)
        Our maximum if 32bits for RGB32 (0xFFRGB)
        :return:
        """
        RGB32_MAX = 0xFFFFFFFF
        entropy_max = log(self.block_size, 2)

        # Correction: (e / e_max) * MAX
        for idx, e in enumerate(self.entropy_d.values()):

            adjusted_entropy = int((e / entropy_max) * RGB32_MAX)

            # Remember, we need strings
            adjusted_entropy_s = struct.pack('>I', adjusted_entropy)
            self.entropy_d[idx] = adjusted_entropy_s

    def jump_to_bin_chunk(self, x, y):
        """
        It calculates the requested binary chunk
        from the position clicked in the image
        :param: (x, y) position in pixels
        :return: Address within the binary
        """
        chunk_nr = (y % self.grid_size) * self.grid_size + x % self.grid_size
        addr = inf_get_min_ea() + chunk_nr * self.block_size

        print("%x" % addr)

        idc.jumpto(addr)
