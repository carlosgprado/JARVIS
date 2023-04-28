#!/usr/bin/python
#
# Name: VulnDetectionWidget.py
# Description: It hosts all GUI elements relevant to vulnerability detection
#


from PyQt5 import QtCore
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QAction
from PyQt5.QtWidgets import QTableWidgetItem, QTreeWidgetItem

from jarvis.widgets.CustomWidget import CustomWidget
import jarvis.core.helpers.Misc as misc


#################################################################
class VulnDetectionWidget(CustomWidget):

    def __init__(self, parent = None):
        """
        Constructor
        """
        CustomWidget.__init__(self)
        self.name = "Bug Hunting"
        self.parent = parent
        self.config = self.parent.config
        self.icon = QIcon(self.icon_path + 'vuln_detection.png')

        # Functionality associated with this widget
        self.vd = parent.vuln_detection
        self.ii = self.vd.ii

        self._createGui()

    def _createGui(self):

        self._createToolBar('Vulnerability')
        self._createToolBarActions()

        self._createOutputTree()
        self._createOutputWindow()
        self._createOutputTable()

        # Output Layout
        self.splitter.addWidget(self.tree_label)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.table_label)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.output_label)
        self.splitter.addWidget(self.output_window)

    def _createToolBarActions(self):

        self.bannedAction = QAction(
                QIcon(self.icon_path + 'banned_ms_functions.png'),
                '&Usage of functions banned by Microsoft',
                self)
        self.bannedAction.triggered.connect(self._showBannedFunctions)

        self.integerAction = QAction(
                QIcon(self.icon_path + 'integer_issues.png'),
                '&Search the whole binary for possible integer issues',
                self)
        self.integerAction.triggered.connect(self._showIntegerIssues)

        self.toolbar.addAction(self.bannedAction)
        self.toolbar.addAction(self.integerAction)

    #################################################################
    # GUI Callbacks
    #################################################################
    def _showBannedFunctions(self):
        """
        Points to functions banned by Microsoft being used.
        """
        self._console_output("Looking for banned functions...")

        deep_search_f = self.config.deep_dangerous_functions

        if deep_search_f:
            self._console_output("Performing a deep search \
                (based on function name)")

        banned_refs_dict = self.vd.find_banned_functions(deep_search_f)

        if not banned_refs_dict:
            self._console_output("[!] No banned functions found", err = True)
            return

        self.tree_label.setText("Functions banned by Microsoft")
        self.tree.clear()
        self.tree.setHeaderLabels(("Banned function", "References", "Name"))

        for f_name, refs in banned_refs_dict.items():
            bf_item = QTreeWidgetItem(self.tree)
            bf_item.setText(0, f_name)

            for ref_addr in refs:
                ref_item = QTreeWidgetItem(bf_item)
                ref_item.setText(1, "0x%x" % ref_addr)
                ref_name = misc.get_function_name(ref_addr)
                ref_item.setText(2, ref_name)

        # Display all items expanded initially
        self.tree.expandAll()

    def _showIntegerIssues(self):
        """
        This is the GUI part of the integer issues functionality
        """
        self._console_output("Looking for integer issues (comparisons)")

        try:
            integer_issues_ins = self.ii.search_integer_issues()
        except NotImplementedError:
            self._console_output("[!] x86_64 not implemented yet", err = True)
            return

        # Is there any integer issues at all?
        nr_rows = len(integer_issues_ins)
        if not nr_rows:
            self._console_output("[-] No integer issues found.")
            return

        self.table.setColumnCount(3)
        self.table_label.setText("Possible integer issues")
        self.table.setHorizontalHeaderLabels(
            ('Address', 'Function name', 'Notes'))
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill with contents
        for idx, ins_ea in enumerate(integer_issues_ins):

            self.table.insertRow(idx)
            addr_item = QTableWidgetItem("%x" % ins_ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            name_item = QTableWidgetItem(misc.get_function_name(ins_ea))
            mnem_item = QTableWidgetItem("")  # placeholder

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, name_item)
            self.table.setItem(idx, 2, mnem_item)
