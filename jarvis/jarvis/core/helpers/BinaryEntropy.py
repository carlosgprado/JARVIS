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
from math import sqrt, log

from Misc import entropy


class BinaryEntropy():
    """
    Calculates the current binary's entropy
    Useful in firmware analysis, for example.
    """

    def __init__(self):
        self.entropy_d = defaultdict(int)
        self.image_width = 200
        self.image_height = 200
        self.nr_cells = 400
        self.scaled_values = [0] * (self.image_width * self.image_height)
        self.tile_size = 0

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
            block_start = MinEA() + (idx * block_size)
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
                    print "[!] Problem calculating block entropy (block %d)" % idx
                    print "[!] Between %08x - %08x" % (block_start, block_start + block_size)
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
        entropy_max = log(self.get_block_size(), 2)

        # Correction: (e / e_max) * MAX
        for idx, e in enumerate(self.entropy_d.itervalues()):

            adjusted_entropy = int((e / entropy_max) * RGB32_MAX)

            # Remember, we need strings
            adjusted_entropy_s = struct.pack('>I', adjusted_entropy)
            self.entropy_d[idx] = adjusted_entropy_s

    def cheap_scale(self):
        """
        In order to scale the Pixmap, I will just modify
        the dataset accordingly.
        Not sure if genius or completely dumb...
        Probably the latter.
        """

        # Get "lines" (in nr. of tiles)
        # Ex. 100 cells = 10 x 10 :)
        tiles_per_row = int(sqrt(self.nr_cells))

        # Tile size (scale factor)
        # For now it is a square, so height = width
        # Ex. 200 px / 10 cells = 20 px / cell
        tile_size = self.image_width / tiles_per_row

        # "Flatten" the dictionary to a list of values
        # This array is "nr_cells" long
        ev = [x for x in self.entropy_d.itervalues()]

        pivots = []
        for j in xrange(tiles_per_row):
            for i in xrange(tiles_per_row):
                p_idx = i * tile_size + j * self.image_width * tile_size
                pivots.append(p_idx)

        # There is a mapping between the pivots
        # and the original entropy values
        for idx in xrange(tiles_per_row * tiles_per_row):
            p = pivots[idx]
            for k in xrange(tile_size):
                for l in xrange(tile_size):
                    self.scaled_values[p + k + (l * self.image_width)] = ev[idx]

    def get_chunk_from_pos(self, x, y):
        """
        It calculates the requested binary chunk
        from the position clicked in the image
        :param: (x, y) position in pixels
        :return: Address within the binary
        """
        pass
