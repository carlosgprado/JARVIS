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
from math import log, sqrt
import struct

from Misc import entropy


class BinaryEntropy():
    """
    Calculates the current binary's entropy
    Useful in firmware analysis, for example.
    """

    def __init__(self):
        self.entropy_d = defaultdict(int)
        self.scaled_values = list()
        self.image_width = 200
        self.image_height = 200
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
        for idx, e in enumerate(self.scaled_values):

            adjusted_entropy = int((e / entropy_max) * RGB32_MAX)

            # Remember, we need strings
            adjusted_entropy_s = struct.pack('>I', adjusted_entropy)
            #self.entropy_d[idx] = adjusted_entropy_s
            self.entropy_d[idx] = '\xFF\x41\x41\x41'


    #################################################################
    # Auxiliary
    #################################################################
    def cheap_scale(self):
        """
        In order to scale the Pixmap, I will just modify
        the dataset accordingly.
        Not sure if genius or completely dumb...
        """

        # Get "lines"
        line_len = int(sqrt(self.nr_cells))
        nr_lines = line_len # squares are nice :)

        # Scale factor
        # For now it is a square, so height = width
        scale_factor = self.image_width / line_len

        # "Flatten" the dictionary to a list of values
        ev = [x for x in self.entropy_d.itervalues()]

        for i in xrange(nr_lines):
            # Each line
            for t in xrange(scale_factor):
                # scale factor "times"
                for j in ev[i * line_len : (i + 1) * line_len]:
                    # Each line element
                    for tt in xrange(scale_factor):
                        self.scaled_values.append(j)
