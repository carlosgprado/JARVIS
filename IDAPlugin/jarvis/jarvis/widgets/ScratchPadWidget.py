#!/usr/bin/python
#
# Name: ScratchPadWidget.py
# Description: A very simple scratchpad for temporal notes
#

import traceback

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QWidget, QTextEdit, QFileDialog
from PyQt5.QtWidgets import QPushButton, QVBoxLayout, QLabel


#################################################################
class ScratchPadWidget(QWidget):

    def __init__(self, parent):
        """
        Constructor
        This widget is kind of different.
        It does not exactly subclass CustomWidget
        """
        QWidget.__init__(self)
        self.name = "Scratchpad"
        self.parent = parent
        self.config = self.parent.config
        self.icon_path = self.config.icons_path
        self.icon = QIcon(self.icon_path + 'pencil.png')

        self._createGui()

    def _createGui(self):

        self._createScratchPadWindow()

        scratchpad_layout = QVBoxLayout()
        save_btn = QPushButton("Save to file", self)
        save_btn.setIcon(QIcon(self.icon_path + 'save-download.png'))
        label = QLabel("Write some notes here")

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

            print("Saved notes to \"%s\"" % filename)

        except Exception as e:
            print("[!] Problem saving notes...")
            print(traceback.format_exc())
