#!/usr/bin/python
#
# Name: OptionsWidget.py
# Description: Visually selecting runtime options
# These are stored in the "main" config object
#

from PySide import QtGui, QtCore
from PySide.QtGui import QIcon, QSpinBox
from PySide.QtGui import QCheckBox, QLabel


#################################################################
class OptionsWidget(QtGui.QWidget):

    def __init__(self, parent):
        """
        Constructor
        """
        QtGui.QWidget.__init__(self)
        self.parent = parent
        self.name = "Options"
        self.config = self.parent.config
        self.iconp = self.config.icons_path
        self.icon = QIcon(self.iconp + 'options.png')

        self._createGui()

    def _createGui(self):
        """
        Grid layout containing groupBoxes
        """
        grid = QtGui.QGridLayout()

        grid.addWidget(self.createBinaryOptions(), 0, 0)
        grid.addWidget(self.createVulnOptions(), 0, 1)

        self.setLayout(grid)

    def createBinaryOptions(self):
        """
        Binary Analysis Options
        """
        groupBox = QtGui.QGroupBox('Binary Analysis')

        # Elements
        cbs_unique_str = QCheckBox('Show unique strings', self)
        cbs_unique_com = QCheckBox('Show unique comments', self)
        cbs_unique_calls = QCheckBox('Show unique calls', self)
        cbs_entropy = QCheckBox('Calculate entropy', self)
        cutoff_label = QLabel('Connect BB cutoff')
        sb_cutoff = QSpinBox()
        sb_cutoff.setRange(1, 40)
        cutoff_func_label = QLabel('Connect functions cutoff')
        sbf_cutoff = QSpinBox()
        sbf_cutoff.setRange(1, 40)

        # Default states are read from the Config
        # class and reflected in the GUI
        cbs_unique_str.setCheckState(
            self.get_state(self.config.display_unique_strings))
        cbs_unique_com.setCheckState(
            self.get_state(self.config.display_unique_comments))
        cbs_unique_calls.setCheckState(
            self.get_state(self.config.display_unique_calls))
        cbs_entropy.setCheckState(
            self.get_state(self.config.calculate_entropy))
        sb_cutoff.setValue(self.config.connect_bb_cutoff)
        sbf_cutoff.setValue(self.config.connect_func_cutoff)

        # Connect elements and signals
        cbs_unique_str.stateChanged.connect(self.string_unique)
        cbs_unique_com.stateChanged.connect(self.comment_unique)
        cbs_unique_calls.stateChanged.connect(self.calls_unique)
        cbs_entropy.stateChanged.connect(self.string_entropy)
        sb_cutoff.valueChanged[int].connect(self.set_cutoff)
        sb_cutoff.valueChanged[int].connect(self.set_func_cutoff)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(cbs_unique_str)
        vbox.addWidget(cbs_unique_com)
        vbox.addWidget(cbs_unique_calls)
        vbox.addWidget(cbs_entropy)
        vbox.addWidget(cutoff_label)
        vbox.addWidget(sb_cutoff)
        vbox.addWidget(cutoff_func_label)
        vbox.addWidget(sbf_cutoff)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)

        return groupBox

    def createVulnOptions(self):
        """
        Vulnerability Discovery related
        """
        groupBox = QtGui.QGroupBox('Vulnerability Discovery')

        # Elements
        cbv_deep_dang = QCheckBox('Deep search for dangerous functions')
        # xxx = QCheckBox('blah')

        # Default states are read from the Options
        # class and reflected in the GUI
        cbv_deep_dang.setCheckState(
            self.get_state(self.config.deep_dangerous_functions))

        # Connect elements and signals
        cbv_deep_dang.stateChanged.connect(self.deep_dangerous)

        vbox = QtGui.QVBoxLayout()
        vbox.addWidget(cbv_deep_dang)
        # vbox.addWidget(xxx)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)

        return groupBox

    ##########################################################################
    # GUI callbacks
    ##########################################################################
    # TODO: OPTIMIZE THIS FOR THE LOVE OF GOD!!!
    def string_unique(self, state):
        self.config.display_unique_strings = (state == QtCore.Qt.Checked)

    def comment_unique(self, state):
        self.config.display_unique_comments = (state == QtCore.Qt.Checked)

    def calls_unique(self, state):
        self.config.display_unique_calls = (state == QtCore.Qt.Checked)

    def string_entropy(self, state):
        self.config.calculate_entropy = (state == QtCore.Qt.Checked)

    def deep_dangerous(self, state):
        self.config.deep_dangerous_functions = (state == QtCore.Qt.Checked)

    def set_cutoff(self, co):
        self.config.connect_bb_cutoff = co

    def set_func_cutoff(self, co):
        self.config.connect_func_cutoff = co

    ##########################################################################
    # Auxiliary
    ##########################################################################
    def get_state(self, option):
        """
        This translates options (boolean)
        to QtCore.Qt.Checked or Unchecked
        """
        if option:
            return QtCore.Qt.Checked

        else:
            return QtCore.Qt.Unchecked
