#!/usr/bin/python
#
# Name: BinaryAnalysisWidget.py
# Description: It hosts all GUI elements relevant to vulnerability detection
#


from PySide import QtGui, QtCore
from PySide.QtGui import QIcon, QStyle, QBrush, QColor
from PySide.QtGui import QTableWidgetItem, QTreeWidgetItem

import jarvis.widgets.CustomWidget as cw
import jarvis.core.helpers.Misc  as misc
from jarvis.core.helpers.InfoUI import InfoUI


#################################################################
class BinaryAnalysisWidget(cw.CustomWidget):

    def __init__(self, parent = None):
        """
        Constructor
        """
        cw.CustomWidget.__init__(self)
        self.name = "Binary analysis"
        self.parent = parent
        self.config = self.parent.config
        self.icon = QIcon(self.iconp + 'binary_analysis.png')

        # Functionality associated with this widget
        self.ba = parent.binary_analysis

        self._createGui()


    def _createGui(self):

        self._createToolBar('Binary')
        self._createToolBarActions()
        self._createOutputWindow()
        self._createOutputTable()
        self._createOutputTree()

        # Output Layout
        self.splitter.addWidget(self.table_label)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.tree_label)
        self.splitter.addWidget(self.tree)
        self.splitter.addWidget(self.output_label)
        self.splitter.addWidget(self.output_window)


    def _createToolBarActions(self):

        self.mostRefAction = QtGui.QAction(
                QIcon(self.iconp + 'most_ref.png'),
                '&Show most referenced functions',
                self,
                triggered = self._showMostReferenced
                )

        self.immCmpsAction = QtGui.QAction(
                QIcon(self.iconp + 'mark_imm_cmps.png'),
                '&Mark immediate compares within the current function. Useful with parsers',
                self,
                triggered = self._markImmCompares
                )


        self.dwCmpsAction = QtGui.QAction(
                QIcon(self.iconp + 'globals_cmp_imm.png'),
                '&Search for global variables being compared to immediate values',
                self,
                triggered = self._showDwordCompares
                )

        self.callsAction = QtGui.QAction(
                QIcon(self.iconp + 'graph_curr_function.png'),
                '&Show calls within the current function',
                self,
                triggered = self._callsInThisFunction
                )

        self.commsAction = QtGui.QAction(
                QIcon(self.iconp + 'comments_curr_function.png'),
                '&Show IDA generated comments within the current function',
                self,
                triggered = self._commentsInThisFunction
                )

        self.stringsAction = QtGui.QAction(
                QIcon(self.iconp + 'strings_curr_function.png'),
                '&Search references to strings within the current function',
                self,
                triggered = self._showStringXrefs
                )

        self.inputsAction = QtGui.QAction(
                QIcon(self.iconp + 'io_connecting_to.png'),
                '&Locate IO connecting to current function. CPU intensive!',
                self,
                triggered = self._showConnectedIO
                )

        self.allFuncsAction = QtGui.QAction(
                QIcon(self.iconp + 'function_list.png'),
                '&Display function list for the connect graph',
                self,
                triggered = self._showAllFunctions
                )

        self.connGraphAction = QtGui.QAction(
                QIcon(self.iconp + 'show_connect_graph.png'),
                '&Shows the connect graph',
                self,
                triggered = self._showConnectionGraph
                )

        self.dangConnAction = QtGui.QAction(
                QIcon(self.iconp + 'connect_io_danger.png'),
                '&Shows all connections between IO input and dangerous functions (CPU intensive!)',
                self,
                triggered = self._showDangerousConnections
                )

        self.bbConnAction = QtGui.QAction(
                QIcon(self.iconp + 'connect_bb.png'),
                '&Shows all connections between selected basic blocks',
                self,
                triggered = self._showConnectedBBs
                )

        self.xorAction = QtGui.QAction(
                QIcon(self.iconp + 'xor_bytes.png'),
                '&XOR the selected bytes with a single byte',
                self,
                triggered = self._xorSelection
                )

        self.toolbar.addAction(self.mostRefAction)
        self.toolbar.addAction(self.dwCmpsAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.immCmpsAction)
        self.toolbar.addAction(self.callsAction)
        self.toolbar.addAction(self.commsAction)
        self.toolbar.addAction(self.stringsAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.inputsAction)
        self.toolbar.addAction(self.allFuncsAction)
        self.toolbar.addAction(self.connGraphAction)
        self.toolbar.addAction(self.dangConnAction)
        self.toolbar.addAction(self.bbConnAction)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.xorAction)


    #################################################################
    # GUI Callbacks
    #################################################################
    def _showMostReferenced(self):
        """
        Shows the most referenced functions.
        """
        self._console_output("Calculating most referenced functions...")
        self.table_label.setText("Most referenced functions")

        most_referenced = self.ba.most_referenced_functions()

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(("Address", "References", "Name"))
        self.table.clearContents()
        self.table.setRowCount(0)

        idx = 0

        # Fill with contents
        for f_ea, (ref_nr, ref_name) in most_referenced:

            self.table.insertRow(idx)
            addr_item = QTableWidgetItem("%x" % f_ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            ref_item =  cw.NumQTableWidgetItem("%d" % ref_nr)
            name_item = QTableWidgetItem(ref_name)

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, ref_item)
            self.table.setItem(idx, 2, name_item)

            idx += 1


    def _markImmCompares(self):
        """
        Marks the immediate compares within the current function
        """
        self.output_window.append("Marking all immediate compares...")
        self.table_label.setText("Immediate compares within current function")

        INS_COLOR = 0x2020c0

        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Address", "Disassembly"))
        self.table.clearContents()
        self.table.setRowCount(0)

        idx = 0
        for cmp_ea, dis in self.ba.find_imm_compares():

            self.table.insertRow(idx)

            addr_item = QTableWidgetItem("%x" % cmp_ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            dis_item =  cw.NumQTableWidgetItem("%s" % dis)

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, dis_item)

            misc.set_ins_color(cmp_ea, INS_COLOR)
            idx += 1


    def _callsInThisFunction(self):
        """
        Shows all calls within the current function
        """
        msg = "Calls within function '" + misc.get_function_name()
        self._console_output(msg)

        show_unique_calls = self.config.display_unique_calls
        callee_list = self.ba.calls_in_function()

        nrows = len(callee_list)
        if not nrows:
            self._console_output("[!] No calls found", err = True)
            return

        self.table_label.setText("Calls within current function")
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Address", "Callee"))
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill with contents
        shown_calls = []

        idx = 0
        for (addr, callee) in callee_list:

            if show_unique_calls and callee in shown_calls:
                continue

            shown_calls.append(callee)

            self.table.insertRow(idx)
            addr_item = QTableWidgetItem("%08x" % addr)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            callee_item =  QTableWidgetItem(callee)
            callee_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, callee_item)

            idx += 1


    def _commentsInThisFunction(self):
        """
        Shows all comments within the current function
        """
        show_unique_c = self.config.display_unique_comments

        msg = "Searching comments within function '" + misc.get_function_name() + "'"
        self._console_output(msg)

        comment_list = self.ba.comments_in_function()

        # Found any comment at all?
        nrows = len(comment_list)
        if not nrows:
            self._console_output("[!] No comments found", err = True)
            return

        self.table.setColumnCount(2)
        self.table_label.setText("Comments within current function")
        self.table.setHorizontalHeaderLabels(("Address", "Comments"))
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill with contents
        displayed_comments = []

        idx = 0
        for (addr, comment) in comment_list:
            if show_unique_c and comment in displayed_comments:
                continue

            displayed_comments.append(comment)

            self.table.insertRow(idx)
            addr_item = QTableWidgetItem("%08x" % addr)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            comment_item =  QTableWidgetItem(comment)

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, comment_item)

            idx += 0


    def _showStringXrefs(self):
        """
        Displays string references in a table
        Optionally Shannon's misc.entropy as well
        """

        # Retrieve some config values
        show_misc_entropy = self.config.calculate_entropy
        show_unique_s = self.config.display_unique_strings

        self._console_output("Calculating string references...")

        self.ba.calculate_strings_list()
        s_ref_list = self.ba.get_string_references()

        # Found any references at all?
        nrows = len(s_ref_list)
        if not nrows:
            self._console_output("[!] No string references found", err = True)
            return

        if show_misc_entropy:
            self.table.setColumnCount(3)
            self.table.setHorizontalHeaderLabels(("Address", "String", "Entropy"))

        else:
            self.table.setColumnCount(2)
            self.table.setHorizontalHeaderLabels(("Address", "String"))

        self.table_label.setText("String references in current function")
        self.table.clearContents()
        self.table.setRowCount(0)

        # Fill the table
        displayed_strings = []

        idx = 0
        for (addr, s) in s_ref_list:
            if show_unique_s and s in displayed_strings:
                continue

            displayed_strings.append(s)

            self.table.insertRow(idx)
            addr_item = QTableWidgetItem("%08x" % addr)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            string_item =  QTableWidgetItem("%s" % s)
            string_item.setFlags(string_item.flags() ^ QtCore.Qt.ItemIsEditable)

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, string_item)

            if show_misc_entropy:
                misc_entropy_item = cw.NumQTableWidgetItem("%.4f" % misc.entropy(s))
                self.table.setItem(idx, 2, misc_entropy_item)

            idx += 1

    def _showDwordCompares(self):
        """
        Inspects the *whole* binary looking for comparisons between
        global dwords and immediate values. These usually contain error
        codes or alike and appear constantly through the code.
        """

        self._console_output("Looking for Dword compares...")
        self.tree_label.setText("Dword immediate compares")

        dw_dict = self.ba.get_dword_compares()

        # Fill the tree with items
        self.tree.setHeaderLabels(("Dword", "Values", "Address"))

        for dw, values in dw_dict.iteritems():
            dw_item = QTreeWidgetItem(self.tree)
            dw_item.setText(0, dw)

            for value, addr in values:
                value_item = QTreeWidgetItem(dw_item)
                value_item.setText(1, value)
                value_item.setText(2, "%x" %addr)

        # Display all items expanded initially
        self.tree.expandAll()


    def _showAllFunctions(self):
        """
        Populates the functions list.
        From this it is possible to select endpoints to
        create a ConnectGraph for example
        """
        self._console_output("Displaying all known functions...")

        current_ea, _ = misc.function_boundaries()

        func_list = self.ba.get_all_functions()
        if not func_list:
            return

        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Address", "Name"))

        self.table_label.setText("Functions in current binary")
        self.table.clearContents()
        self.table.setRowCount(0)

        # Current table index
        c_idx = 0

        for idx, (f_ea, f_name) in enumerate(func_list):
            self.table.insertRow(idx)

            addr_item = QTableWidgetItem("%08x" % f_ea)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            name_item = QTableWidgetItem("%s" % f_name)

            if f_ea == current_ea:
                current_ea_item = addr_item
                c_idx = idx

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, name_item)

        # Conveniently scroll to the current EA
        self.table.scrollToItem(
            #current_ea_item,
            self.table.item(c_idx, 0),
            QtGui.QAbstractItemView.PositionAtTop
            )


    def _showConnectionGraph(self):
        """
        Creates and shows a ConnectGraph between orig and dest.
        """
        self._console_output("Creating connect graph...")
        res = True

        try:
            u = InfoUI.function_orig_ea
            v = InfoUI.function_dest_ea

        except:
            self._console_output("[!] You must select the corresponding functions", err = True)


        cg = self.ba.get_connect_graph(u, v)
        res = self.ba.show_connect_graph(cg)

        if not res:
            self._console_output(
                "[x] No connection between %08x and %08x" % (u, v),
                err = True)


    def _showConnectedIO(self):
        """
        Shows a list of functions dealing with IO and
        connected to the current function
        """
        self._console_output("Calculating file & network IO...")
        io_list = self.ba.input_to_function()

        if not io_list:
            self._console_output("[!] No (obvious) IO connecting to this function", err = True)
            return

        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Caller", "Name"))

        self.table_label.setText("Connected IO")
        self.table.clearContents()
        self.table.setRowCount(0)

        for idx, caller in enumerate(io_list):
            self.table.insertRow(idx)

            addr_item = QTableWidgetItem("%08x" % caller)
            addr_item.setFlags(addr_item.flags() ^ QtCore.Qt.ItemIsEditable)
            name_item = QTableWidgetItem("%s" % misc.get_function_name(caller))

            self.table.setItem(idx, 0, addr_item)
            self.table.setItem(idx, 1, name_item)


    def _showDangerousConnections(self):
        """
        Shows connections graphs between functions calling IO
        and the ones calling dangerous APIs
        """
        self._console_output("Calculating dangerous connections...")
        conn_graphs = self.ba.get_all_dangerous_connections()

        if not conn_graphs:
            self._console_output("[!] No (obvious) dangerous connections", err = True)
            return

        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(("IO Caller", "Dangerous Functions", "Shortest Path Length", "u", "v"))

        self.table_label.setText("Dangerous Connections")
        self.table.clearContents()
        self.table.setRowCount(0)

        for idx, c in enumerate(conn_graphs):
            self.table.insertRow(idx)

            u, v, sp_len = c    # tuple unpacking
            io_item = QTableWidgetItem("%s" % misc.get_function_name(u))
            df_item = QTableWidgetItem("%s" % misc.get_function_name(v))
            sp_item = QTableWidgetItem("%d" % sp_len)
            ioa_item = QTableWidgetItem("%x" % u)
            ioa_item.setFlags(ioa_item.flags() ^ QtCore.Qt.ItemIsEditable)
            dfa_item = QTableWidgetItem("%x" % v)
            dfa_item.setFlags(dfa_item.flags() ^ QtCore.Qt.ItemIsEditable)

            self.table.setItem(idx, 0, io_item)
            self.table.setItem(idx, 1, df_item)
            self.table.setItem(idx, 2, sp_item)
            self.table.setItem(idx, 3, ioa_item)
            self.table.setItem(idx, 4, dfa_item)


    def _showConnectedBBs(self):
        """
        Shows a list of paths between selected basic blocks
        """
        self._console_output("Calculating paths between basic blocks...")
        bb_paths = self.ba.get_bb_connect_graph(self.config.connect_bb_cutoff)

        if not bb_paths:
            self._console_output("[!] Could not find paths between basic blocks", err = True)
            return

        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(("Path ID", "Length"))

        # Override the default double click callback
        self.table.cellDoubleClicked.connect(self._bbTableDoubleClicked)

        self.table_label.setText("Paths between Basic Blocks")
        self.table.clearContents()
        self.table.setRowCount(0)

        bb_paths_l = list(bb_paths) # To reference by index :)

        if len(bb_paths_l) == 0:
            self._console_output("[!] Could not find paths. Try increasing cutoff under Options", err = True)
            return

        for idx, path in enumerate(bb_paths_l):
            self.table.insertRow(idx)

            path_item = QTableWidgetItem("%d" % idx)
            path_item.setFlags(path_item.flags() ^ QtCore.Qt.ItemIsEditable)
            len_item = cw.NumQTableWidgetItem("%d" % len(path))
            len_item.setFlags(len_item.flags() ^ QtCore.Qt.ItemIsEditable)

            self.table.setItem(idx, 0, path_item)
            self.table.setItem(idx, 1, len_item)

        # Cache this
        self.ba.cache.bb_paths = bb_paths_l


    def _bbTableDoubleClicked(self, row, col):
        """
        This overrides the callback for table's double click
        set in the CustomWidget object.
        Apparently if there is an exception it falls back to
        the original callback... Not sure why this behaviour.
        NOTE: This is kind of nasty.
        :return: None
        """
        it = self.table.item(row, col).text()

        try:
            idx = int(it)   # decimal
            bb_path = self.ba.cache.bb_paths[idx]

            col = QtGui.QColorDialog.getColor()
            if col.isValid():
                # IDA works with BGR (annoying)
                ida_color = misc.pyside_to_ida_color(col.name())
                misc.paint_basic_blocks(bb_path, ida_color)

            else:
                print '[x] Invalid QColor'

            return

        except IndexError:
            # Address value (does not contain [A-F]) is interpreted as index
            return

        except ValueError:
            # Address value (containing [A-F]) fucks up int()
            return


    def _xorSelection(self):
        """
        It XORs the selected bytes with a single-byte key
        WARNING: it can brick your IDB!!!1!
        """

        self._console_output("XOR'ing selected bytes...")
        self.ba.xor_patcher()

