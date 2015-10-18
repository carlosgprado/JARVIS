#!/usr/bin/python
#
# Name: CustomWidget.py
# Description: This is a "super" widget. All others must subclass it
#
# NOTE: Do not die trying to be very smart
#

from PySide import QtGui, QtCore
from PySide.QtGui import QIcon, QColor
from PySide.QtGui import QTextEdit, QSplitter
from PySide.QtGui import QTableWidget, QTreeWidget

from jarvis.core.helpers.Misc import jump_to_address
from jarvis.Config import JConfig
from jarvis.core.helpers.InfoUI import InfoUI


#################################################################
class CustomWidget(QtGui.QMainWindow):

    def __init__(self):
        """
        Constructor
        """
        QtGui.QMainWindow.__init__(self)
        self.name = "Custom widget"
        self.central_widget = QtGui.QWidget()
        self.setCentralWidget(self.central_widget)

        # TODO: This is ugly, improve it
        self.iconp = JConfig().icons_path

        self._createLayout()

    def _createGui(self):
        """
        Subclasses must override this
        depending on the elements they want to add
        self._createOutputTree(),
        self._createOutputTable(),
        self._createOutputWindow() and add them to
        the corresponding layouts.
        """
        raise NotImplementedError

    def _createToolBar(self, name):
        """
        Subclasses need to define the
        specific Actions
        """
        self.toolbar = self.addToolBar(name)
        self.toolbar.setMovable(False)

    def _createLayout(self):
        """
        This creates the basic layout:
        Buttons & Outputs
        """

        # Layouts (This is a common disposition)
        main_layout = QtGui.QVBoxLayout()
        self.button_layout = QtGui.QHBoxLayout()
        output_layout = QtGui.QVBoxLayout()

        # You will need to create your buttons
        # and add them to your layout like this:
        # self.button_layout.addWidget(button_1)

        # Output Layout Inner (QSplitter)
        # Add as many widgets as you please
        # They will be ordered vertically and
        # be resizable by the user
        # self.splitter.addWidget(self.table_label)
        # self.splitter.addWidget(...)
        self.splitter = QSplitter(QtCore.Qt.Vertical)

        # Nested layouts
        main_layout.addLayout(self.button_layout)
        output_layout.addWidget(self.splitter)
        main_layout.addLayout(output_layout)
        self.central_widget.setLayout(main_layout)

    def _createOutputWindow(self):
        """
        Some binary analysis commands will output to this.
        """

        self.output_label = QtGui.QLabel('Output')

        self.output_window = QTextEdit()
        self.output_window.setFontPointSize(10)
        self.output_window.setReadOnly(True)
        # Save it for later use
        self.output_window.original_textcolor = self.output_window.textColor()

    def _createOutputTable(self):
        """
        A vanilla QTableWidget. Callbacks modify
        its properties, like number of columns, etc.
        """
        self.table_label = QtGui.QLabel('Table Output')

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 300)
        self.table.setColumnWidth(2, 300)

        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

        # Connect signals to slots
        self.table.customContextMenuRequested.connect(self._tablePopup)
        self.table.horizontalHeader().sectionDoubleClicked.connect(
            self._tableHeaderDoubleClicked)
        self.table.cellDoubleClicked.connect(self._tableCellDoubleClicked)

    def _createOutputTree(self):
        """
        A QtreeWidget. Initially used to display those pesky
        dword comparison to immediate values.
        """
        self.tree_label = QtGui.QLabel('Tree Output')

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setColumnWidth(0, 150)
        self.tree.setColumnWidth(1, 150)
        self.tree.setColumnWidth(2, 50)

        # Connect signals to slots
        self.tree.itemDoubleClicked.connect(self._treeElementDoubleClicked)

    #################################################################
    # GUI Callbacks
    #################################################################
    def _console_output(self, s = "", err = False):
        """
        Convenience wrapper
        """
        if err:
            # Error message
            err_color = QColor('red')
            self.output_window.setTextColor(err_color)
            self.output_window.append(s)
            # restore original color
            self.output_window.setTextColor(
                self.output_window.original_textcolor)

        else:
            self.output_window.append(s)

    def _tableCellDoubleClicked(self, row, col):
        """
        Most of the info displayed in QTableWidgets represent addresses.
        Default action: try to jump to it.
        """
        it = self.table.item(row, col).text()

        try:
            addr = int(it, 16)
            jump_to_address(addr)

        except ValueError:
            self._console_output("[!] That does not look like an address...", err = True)
            return

    def _tablePopup(self, pos):
        """
        Popup menu activated clicking the secondary
        button on the table
        """
        menu = QtGui.QMenu()

        # Add menu entries
        delRow = menu.addAction(QIcon(self.iconp + "close.png"), "Delete Row")
        selItem = menu.addAction(
            QIcon(self.iconp + "bookmark.png"), "Mark entry")
        menu.addSeparator()
        origFunc = menu.addAction(
            QIcon(self.iconp + "lightning.png"), "Select origin function")
        destFunc = menu.addAction(
            QIcon(self.iconp + "flag.png"), "Select destination function")

        # Get entry clicked
        action = menu.exec_(self.mapToGlobal(pos))

        # Dispatch :)
        if action == delRow:
            self.table.removeRow(self.table.currentRow())

        elif action == selItem:
            self.table.currentItem().setBackground(QtGui.QColor('red'))

        elif action == origFunc:
            try:
                addr = self.table.currentItem().text()
                InfoUI.function_orig_ea = int(addr, 16)

            except:
                self._console_output("This does not look like an address...", err = True)

        elif action == destFunc:
            try:
                addr = self.table.currentItem().text()
                InfoUI.function_dest_ea = int(addr, 16)

            except:
                self._console_output("This does not look like an address...", err = True)

    def _tableHeaderDoubleClicked(self, index):
        """
        Used to sort the contents
        """
        self.table.sortItems(index, order = QtCore.Qt.AscendingOrder)

    def _treeElementDoubleClicked(self, item, column):
        """
        QTreeWidgetElement callback. Basically it jumps to
        the selected address in IDA disassembly window.
        """
        try:
            # Only interested in addresses
            addr_int = int(item.text(column), 16)
            jump_to_address(addr_int)
            # Paint some color
            item.setBackground(column, QtGui.QColor('green'))

        except:
            self._console_output("[!] That does not look like an address...", err = True)


#################################################################
class NumQTableWidgetItem(QtGui.QTableWidgetItem):
    """
    Overload __lt__ to be able to sort numerically
    Default sorting is alphabetically
    """

    def __lt__(self, x):
        return float(self.text()) < float(x.text())
