#!/usr/bin/python
#
# Name: config.py
# Description: The configuration options in a convenient format
#
import os

class JConfig():

    def __init__(self):
        """
        This is ridiculous.
        Python definitely needs some kind of "C-like structure"
        """

        # Paths, etc.
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        self.icons_path = self.root_dir + os.sep + 'images' + os.sep

        # Strings
        self.display_unique_strings = False
        self.display_unique_comments = False
        self.display_unique_calls = False
        self.calculate_entropy = False

        # Function / BB path related
        self.connect_bb_cutoff = 20
        self.connect_func_cutoff = 12


        # Vulnerability analysis
        self.deep_dangerous_functions = True

