#!/usr/bin/python
#
# Name: Firmware.py
#
# Description: Craig's stuff conveniently accessible
#


from idc import *
from idaapi import *
from idautils import *

# Craig Heffner's RE sauce
from jarvis.core.helpers.Rizzo import RizzoBuild, RizzoApply
from jarvis.core.helpers.Codatify import Codatify


class Firmware():

    def __init__(self):
        print("= Loading Firmware module...")

    def rizzo_produce(self, say):
        fname = ask_file(1, "*.riz", "Save signature file as")
        if fname:
            if '.' not in fname:
                fname += ".riz"
            return RizzoBuild(say, fname)

    def rizzo_load(self, say):
        fname = ask_file(0, "*.riz", "Load signature file")
        if fname:
            return RizzoApply(say, fname)

    def fix_code(self, say):
        cd = Codatify(say)
        cd.codeify()

    def fix_data(self, say):
        cd = Codatify(say)
        cd.stringify()
        cd.datify()
        cd.pointify()
