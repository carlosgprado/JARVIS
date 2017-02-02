#!/usr/bin/python
#
# Name: ScratchPadWidget.py
# Description: A very simple scratchpad for temporal notes
#

import traceback

from PySide import QtGui
from PySide.QtGui import QTextEdit, QIcon, QFileDialog


#################################################################
class ScratchPadWidget(QtGui.QWidget):

    def __init__(self, parent):
        """
        Constructor
        This widget is kind of different.
        It does not exactly subclass CustomWidget
        """
        QtGui.QWidget.__init__(self)
        self.name = "Scratchpad"
        self.parent = parent
        self.config = self.parent.config
        self.iconp = self.config.icons_path
        self.icon = QIcon(self.iconp + 'pencil.png')

        self._createGui()

    def _createGui(self):

        self._createScratchPadWindow()

        scratchpad_layout = QtGui.QVBoxLayout()
        save_btn = QtGui.QPushButton("Save to file", self)
        save_btn.setIcon(QIcon(self.iconp + 'save-download.png'))
        label = QtGui.QLabel("Write some notes here")

        scratchpad_layout.addWidget(label)
        scratchpad_layout.addWidget(self.scratchpad_window)
        scratchpad_layout.addWidget(save_btn)

        # Connect signals and slots
        save_btn.clicked.connect(self._saveButtonClicked)
        self.setLayout(scratchpad_layout)

    def _createScratchPadWindow(self):
        """
        Some binary analysis commands will output to this.
        """
        self.scratchpad_window = QTextEdit()
        self.scratchpad_window.setFontPointSize(9)

    #################################################################
    # GUI Callbacks
    #################################################################
    def _saveButtonClicked(self):

        try:
            filename, flt = QFileDialog.getSaveFileName(
                self,
                "File to save notes",
                "",
                selectedFilter = '*.txt')

            sp_text = self.scratchpad_window.toPlainText()

            with open(filename, 'w') as f:
                f.write(sp_text)

            print "Saved notes to \"%s\"" % filename

        except:
            print "[!] Problem saving notes..."
            print traceback.format_exc()
