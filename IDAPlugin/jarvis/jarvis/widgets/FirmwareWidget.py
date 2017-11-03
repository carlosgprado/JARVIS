#!/usr/bin/python
#
# Name: VulnDetectionWidget.py
# Description: It hosts all GUI elements relevant to vulnerability detection
#

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QAction

from jarvis.widgets.CustomWidget import CustomWidget
import jarvis.core.helpers.BinaryEntropy as BE


#################################################################
class FirmwareWidget(CustomWidget):

    def __init__(self, parent = None):
        """
        Constructor
        """
        CustomWidget.__init__(self)
        self.name = "Firmware"
        self.parent = parent
        self.config = self.parent.config
        self.icon = QIcon(self.icon_path + 'vuln_detection.png')
        self.img_data = None

        # Functionality associated with this widget
        self.fw = parent.firmware
        self.binary_entropy = BE.BinaryEntropy()

        self._createGui()

    def _createGui(self):

        self._createToolBar('Firmware')
        self._createToolBarActions()

        self._createOutputWindow()
        self._createOutputTable()

        # Output Layout
        self.splitter.addWidget(self.table_label)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.output_label)
        self.splitter.addWidget(self.output_window)

    def _createToolBarActions(self):

        self.rizzoProduceAction = QAction(
                QIcon(self.icon_path + 'tag-add.png'),
                '&Generate Rizzo signatures',
                self)
        self.rizzoProduceAction.triggered.connect(self._rizzo_produce)

        self.rizzoLoadAction = QAction(
                QIcon(self.icon_path + 'tag-icon.png'),
                '&Apply Rizzo signatures',
                self)
        self.rizzoLoadAction.triggered.connect(self._rizzo_load)

        self.codatifyFixCode = QAction(
                QIcon(self.icon_path + 'processor-icon.png'),
                '&Fix Code',
                self)
        self.codatifyFixCode.triggered.connect(self._codatify_fix_code)

        self.codatifyFixData = QAction(
                QIcon(self.icon_path + 'server_components.png'),
                '&Fix Data',
                self)
        self.codatifyFixData.triggered.connect(self._codatify_fix_data)

        self.toolbar.addAction(self.rizzoProduceAction)
        self.toolbar.addAction(self.rizzoLoadAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.codatifyFixCode)
        self.toolbar.addAction(self.codatifyFixData)

    #################################################################
    # GUI Callbacks
    #################################################################
    def _rizzo_produce(self):
        self._console_output("Building Rizzo signatures, this may take a few minutes...")
        delta = self.fw.rizzo_produce(self._console_output)
        self._console_output("Built signatures in {0} seconds".format(delta))

    def _rizzo_load(self):
        self._console_output("Applying Rizzo signatures, this may take a few minutes...")
        ret = self.fw.rizzo_load(self._console_output)
        if ret:
            count, delta = ret
            self._console_output("Applied {0} signatures in {0} seconds".format(count, delta))

    def _codatify_fix_code(self):
        self.fw.fix_code(self._console_output)

    def _codatify_fix_data(self):
        self.fw.fix_data(self._console_output)

    def _notImplementedYet(self):
        """
        Placeholder
        """
        pass
