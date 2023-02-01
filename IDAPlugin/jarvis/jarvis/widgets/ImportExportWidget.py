#!/usr/bin/python
#
# Name: ImportExportWidget.py
# Description: It deals with ECC. No, just kidding
#

import traceback

from PyQt5 import QtCore, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QTableWidgetItem, QAction, QColorDialog

from jarvis.widgets.CustomWidget import CustomWidget
import jarvis.core.helpers.Misc as misc
from jarvis.core.helpers.Patching import patch_binary


#################################################################
class ImportExportWidget(CustomWidget):

    def __init__(self, parent = None):
        """
        Constructor
        """
        CustomWidget.__init__(self)
        self.name = "Import / Export"
        self.parent = parent
        self.config = self.parent.config
        self.icon = QIcon(self.icon_path + 'import_export.png')

        # Functionality associated with this widget
        self.ie = parent.import_export

        self._createGui()

    def _createGui(self):

        self._createToolBar('ImportExport')
        self._createToolBarActions()
        self._createOutputWindow()
        self._createOutputTable()

        # Output Layout
        self.splitter.addWidget(self.table_label)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.output_label)
        self.splitter.addWidget(self.output_window)

    def _createToolBarActions(self):

        self.impTraceAction = QAction(
                QIcon(self.icon_path + 'import_pin_trace.png'),
                '&Import a PIN trace from file',
                self)
        self.impTraceAction.triggered.connect(self._showImportTrace)

        self.expGraphmlAction = QAction(
                QIcon(self.icon_path + 'export_trace_graphml.png'),
                '&Export current PIN trace to GraphML',
                self)
        self.expGraphmlAction.triggered.connect(self._showExportTraceGraphML)

        self.dynamicCallsAction = QAction(
                QIcon(self.icon_path + 'import_dyncall_info.png'),
                '&Import dynamic call resolution information from PIN tool',
                self)
        self.dynamicCallsAction.triggered.connect(self._showDynamicCalls)

        self.exportAction = QAction(
                QIcon(self.icon_path + 'export_function_bytes.png'),
                '&Export the current function code (ascii hex encoded)',
                self)
        self.exportAction.triggered.connect(self._showExportFunction)

        self.patchAction = QAction(
                QIcon(self.icon_path + 'patch_binary.png'),
                '&Patch the original binary with the IDA modifications',
                self)
        self.patchAction.triggered.connect(self._patchBinary)

        self.toolbar.addAction(self.impTraceAction)
        self.toolbar.addAction(self.expGraphmlAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.dynamicCallsAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.exportAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.patchAction)

    #################################################################
    # GUI Callbacks
    #################################################################
    def _showImportTrace(self):
        """
        This is the GUI part of the PIN trace import functionality
        """
        self._console_output("Importing PIN trace information from file...")

        # Color for the basic blocks hit during the trace
        col = QColorDialog.getColor()
        if col.isValid():
            # IDA works with BGR (annoying)
            ida_color = misc.pyside_to_ida_color(col.name())
        else:
            # Probably closed the QColorDialog
            self._console_output("[!] Problem getting color for trace. Aborting.")
            return

        try:
            imported_info_dict = self.ie.ti.import_data(ida_color)
        except Exception as e:
            self._console_output("[!] Problem importing from file", err = True)
            self._console_output(traceback.format_exc(), err = True)
            return

        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ('Thread ID', 'From', 'To', 'From (name)', 'To (name)'))
        self.table_label.setText("Imported information from PIN trace")
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill with contents
        # TODO: This could be better in a QTree or maybe adding
        # a drop down menu to select the thread id...
        idx = 0
        for tid, call_list in imported_info_dict.items():
            self._console_output("Processing Thread ID %d" % tid)

            for u_ea, v_ea in call_list:

                self.table.insertRow(idx)
                tid_item = QTableWidgetItem("%d" % tid)
                u_item = QTableWidgetItem("%x" % u_ea)
                u_item.setFlags(u_item.flags() ^ QtCore.Qt.ItemIsEditable)
                v_item = QTableWidgetItem("%x" % v_ea)
                v_item.setFlags(v_item.flags() ^ QtCore.Qt.ItemIsEditable)
                from_item = QTableWidgetItem(misc.get_function_name(u_ea))
                to_item = QTableWidgetItem(misc.get_function_name(v_ea))

                self.table.setItem(idx, 0, tid_item)
                self.table.setItem(idx, 1, u_item)
                self.table.setItem(idx, 2, v_item)
                self.table.setItem(idx, 3, from_item)
                self.table.setItem(idx, 4, to_item)

                idx += 1

    def _showExportTraceGraphML(self):
        """
        This very long and comprehensive name says it all :)
        """
        self._console_output("Exporting trace to GraphML...")

        ret = self.ie.ti.export_to_graphml()
        if not ret:
            self._console_output("Error exporting trace to GraphML", err = True)

        else:
            self._console_output("Exported successfully")

    def _showDynamicCalls(self):
        """
        Imports information regarding dynamic calls from a previous
        PIN tool trace.
        """
        self._console_output("Importing dynamic call resolution information...")

        try:
            # TODO: display the results in the widget
            dyn_calls = self.ie.ti.import_dynamic_calls()

        except Exception as e:
            self._console_output("[!] Problem importing dynamic calls", err = True)
            self._console_output(traceback.format_exc(), err = True)
            return

    def _showExportFunction(self):
        """
        Exports the current function code, ascii hex encoded
        This is useful to import into tools like miasm and alike
        """
        self._console_output("Exporting the current function...")
        self.ie.export_current_function()

    def _patchBinary(self):
        """
        Exports the current function code, ascii hex encoded
        This is useful to import into tools like miasm and alike
        """
        self._console_output("Patching the original binary...")
        pl = patch_binary()

        if not pl:
            self._console_output("[!] No bytes to patch", err = True)
            return

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(
            ('File offset', 'Original', 'Patched'))
        self.table_label.setText("Patched bytes exported to file")
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill with contents
        for idx, (fpos, o, p) in enumerate(pl):

            self.table.insertRow(idx)
            fpos_item = QTableWidgetItem("%x" % fpos)
            fpos_item.setFlags(fpos_item.flags() ^ QtCore.Qt.ItemIsEditable)
            orig_item = QTableWidgetItem("%x" % o)
            patch_item = QTableWidgetItem("%x" % p)

            self.table.setItem(idx, 0, fpos_item)
            self.table.setItem(idx, 1, orig_item)
            self.table.setItem(idx, 2, patch_item)

        self._console_output("Done patching. Look in the same directory as the original for a .patched file")
