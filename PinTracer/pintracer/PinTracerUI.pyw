#
# Main file (PySide GUI controls "model")
#

import sys
import subprocess
import process_json_traces as pjt

from PySide import QtGui
from PySide import QtCore
from PySide.QtGui import QApplication, QMainWindow, QStatusBar, QIcon, QRadioButton
from PySide.QtGui import QWidget, QGroupBox, QPushButton, QLineEdit, QComboBox
from PySide.QtGui import QFormLayout, QLabel, QProgressBar, QMessageBox
from PySide.QtGui import QVBoxLayout, QHBoxLayout, QStyle, QCheckBox



class MainWindow(QMainWindow):

    def __init__(self):
        """
        Constructor
        """
        QMainWindow.__init__(self)
        self.setWindowIcon(QIcon('icons/flask.png'))
        self.setWindowTitle('PIN Tracer')
        self.setGeometry(300, 250, 800, 350)

    def setupStatusBar(self):
        """
        TODO: some other widget maybe
        """
        self.myStatusBar = QStatusBar()
        self.myStatusBar.showMessage('Ready', 0)
        self.setStatusBar(self.myStatusBar)


    def executableGB(self):
        """
        Options related to the execution of the
        process we want to trace
        """
        groupbox = QGroupBox('Executable options')

        name_label = QLabel('Executable name')
        args_label = QLabel('Executable arguments')
        out_label = QLabel('Output file')
        bits_label = QLabel('Binary type')

        self.exec_name_edit = QLineEdit()
        self.exec_args_edit = QLineEdit()
        self.out_file_edit = QLineEdit()
        self._32_bits = QRadioButton('32 bits')
        self._32_bits.setChecked(True)

        self._64_bits = QRadioButton('64 bits')

        browseButtonExe = QPushButton('Browse')
        browseButtonExe.clicked.connect(self.browseFileExe)

        browseButtonOutput = QPushButton('Browse')
        browseButtonOutput.clicked.connect(self.browseFileOutput)

        vbox = QFormLayout()

        hboxExe = QHBoxLayout()
        hboxExe.addWidget(self.exec_name_edit)
        hboxExe.addWidget(browseButtonExe)

        hboxOutput = QHBoxLayout()
        hboxOutput.addWidget(self.out_file_edit)
        hboxOutput.addWidget(browseButtonOutput)

        hBoxBits = QHBoxLayout()
        hBoxBits.addWidget(self._32_bits)
        hBoxBits.addWidget(self._64_bits)

        vbox.setFormAlignment(QtCore.Qt.AlignLeft)
        vbox.addRow(name_label, hboxExe)
        vbox.addRow(out_label, hboxOutput)
        vbox.addRow(args_label, self.exec_args_edit)
        vbox.addRow(bits_label, hBoxBits)

        groupbox.setLayout(vbox)

        return groupbox


    def optionsGB(self):
        """
        Options related to the execution of the
        process we want to trace
        """
        groupbox = QGroupBox('Tracing options')

        self.log_bb_cb = QCheckBox('Log basic blocks', self)

        self.hit_only_cb = QCheckBox('Hit only', self)
        self.hit_only_cb.setCheckState(QtCore.Qt.Checked)

        self.main_only_cb = QCheckBox('Main only', self)
        self.main_only_cb.setCheckState(QtCore.Qt.Checked)

        only_this_label = QLabel('Trace only this binary')
        self.only_this_edit = QLineEdit()
        self.pin_bin_location_edit = QLineEdit()
        browseButtonPin = QPushButton('Browse')
        browseButtonPin.clicked.connect(self.browsePinBinary)

        vbox = QVBoxLayout()

        pin_bin_label = QLabel('Location PIN Binaries')
        hboxPin = QHBoxLayout()
        hboxPin.addWidget(self.pin_bin_location_edit)
        hboxPin.addWidget(browseButtonPin)

        options_form_layout = QFormLayout()
        options_form_layout.setFormAlignment(QtCore.Qt.AlignLeft)
        options_form_layout.addRow(only_this_label, self.only_this_edit)
        options_form_layout.addRow(pin_bin_label, hboxPin)

        vbox.addLayout(options_form_layout)
        vbox.addWidget(self.hit_only_cb)
        vbox.addWidget(self.main_only_cb)
        vbox.addWidget(self.log_bb_cb)

        groupbox.setLayout(vbox)

        return groupbox


    def compareGB(self):
        """
        Compare two traces to find interesting code
        """
        groupbox = QGroupBox('Differential tracing')

        self.firstTrace = QRadioButton('First trace (noise)')
        self.secondTrace = QRadioButton('Second trace (signal)')
        compareButton = QPushButton('Compare')
        compareButton.clicked.connect(self.compareTraces)

        vbox = QVBoxLayout()
        vbox.addWidget(self.firstTrace)
        vbox.addWidget(self.secondTrace)
        vbox.addWidget(compareButton)
        groupbox.setLayout(vbox)

        return groupbox


    def setupCentralWidget(self):
        """
        This is the GUI heart
        """
        self.centralWidget = QWidget()
        hLayout = QtGui.QHBoxLayout(self)
        vLayout = QtGui.QVBoxLayout(self)

        hLayout.addWidget(self.executableGB())

        vLayout.addWidget(self.optionsGB())
        vLayout.addWidget(self.compareGB())

        hLayout.addLayout(vLayout)

        self.centralWidget.setLayout(hLayout)
        self.setCentralWidget(self.centralWidget)


    def setupToolBar(self):
        self.mainToolBar = self.addToolBar('Main')
        self.mainToolBar.setMovable(True)

        # Define Actions here. They translate roughly
        # to "buttons" in the GUI
        self.startAction = QtGui.QAction(
                QIcon('icons/play.png'),
                '&Start tracing with selected options',
                self,
                shortcut = 'Ctrl+T',
                statusTip = 'Start tracing',
                triggered = self.startTracing
                )

        self.pauseAction = QtGui.QAction(
                QIcon('icons/pause.png'),
                '&Pause Tracing',
                self,
                shortcut = 'Ctrl+P',
                statusTip = 'Pause tracing',
                triggered = self.pauseTracing
                )

        self.stopAction = QtGui.QAction(
                QIcon('icons/stop.png'),
                '&Stop Tracing completely',
                self,
                shortcut = 'Ctrl+S',
                statusTip = 'Stop tracing',
                triggered = self.stopTracing
                )

        self.optionsAction = QtGui.QAction(
                QIcon('icons/options-edit.png'),
                '&Configure program options',
                self,
                shortcut = 'Ctrl+O',
                statusTip = 'Program options',
                triggered = self.editOptions
                )

        self.logAction = QtGui.QAction(
                QIcon('icons/log.png'),
                '&Show runtime log',
                self,
                shortcut = 'Ctrl+L',
                statusTip = 'Show log',
                triggered = self.showLog
                )

        self.aboutAction = QtGui.QAction(
                QIcon('icons/info.png'),
                '&About this program',
                self,
                shortcut = 'Ctrl+B',
                statusTip = 'About',
                triggered = self.showAbout
                )

        self.quitAction = QtGui.QAction(
                QIcon('icons/close.png'),
                '&Close this program',
                self,
                shortcut = 'Ctrl+K',
                statusTip = 'Close',
                triggered = self.quitProgram
                )


        # Add Actions to the ToolBar
        self.mainToolBar.addAction(self.startAction)
        self.mainToolBar.addAction(self.pauseAction)
        self.mainToolBar.addAction(self.stopAction)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.optionsAction)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.logAction)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.aboutAction)
        self.mainToolBar.addSeparator()
        self.mainToolBar.addAction(self.quitAction)


    ####################################################################
    # GUI CALLBACKS
    ####################################################################
    def startTracing(self):
        """
        This is just a subprocess wrapper :)
        A typical command line invocation would be:
        pin_bat.bat -t PinTracer32_json.dll [-only <path>] -- <path> [exe_args]
        """
        argumentz = []

        # PIN binary
        if self.pin_bin_location_edit.text():
            argumentz.append(self.pin_bin_location_edit.text())

        else:
            QMessageBox.critical(
                self,
                'Error',
                'Location of Intel PIN binaries?'
                )

            return

        # The PinTool DLL
        argumentz.append('-t')
        if self._32_bits.isChecked():
            argumentz.append('PinTracer32_json.dll')

        else:
            argumentz.append('PinTracer64_json.dll')

        # PinTool options
        if self.only_this_edit.text():
            argumentz.append('-only')
            argumentz.append(self.only_this_edit.text())


        # Differential debugging
        # Is this option checked?
        if self.firstTrace.isChecked():
            QMessageBox.warning(
                self,
                'Warning',
                'Saving trace as noise.json'
                )
            argumentz.append('-o')
            argumentz.append('noise.json')

        elif self.secondTrace.isChecked():
            QMessageBox.warning(
                self,
                'Warning',
                'Saving trace as signal.json'
                )
            argumentz.append('-o')
            argumentz.append('signal.json')

        elif self.out_file_edit.text():
            argumentz.append('-o')
            argumentz.append(self.out_file_edit.text())


        if not self.hit_only_cb.isChecked():
            argumentz.append('-hit')
            argumentz.append('0')

        if not self.main_only_cb.isChecked():
            argumentz.append('-main')
            argumentz.append('0')


        # Finally the executable to trace :)
        if self.exec_name_edit.text():
            argumentz.append('--')
            argumentz.append(self.exec_name_edit.text())

        else:
            QMessageBox.critical(
                self,
                'Error',
                'You need to specify an executable!'
                )

            return

        # Plus optional arguments
        if self.exec_args_edit.text():
            argumentz.append("%s" % self.exec_args_edit.text())


        # Do it faggot!
        print argumentz     # debug
        self.myStatusBar.showMessage('Tracing...', 0)
        subprocess.call(argumentz, shell = False)
        self.myStatusBar.showMessage('Done', 0)


    def pauseTracing(self):
        self.notYet()


    def stopTracing(self):
        self.notYet()


    def editOptions(self):
        self.notYet()


    def showLog(self):
        self.notYet()


    def compareTraces(self):
        """
        TODO: ASLR is a pain in the ass.
        I need to rebase the traces to a common image base
        and then compare.
        """
        self.myStatusBar.showMessage('Diffing both traces...')

        j_noise = pjt.load_trace_from_file('noise.json')
        j_signal = pjt.load_trace_from_file('signal.json')

        # Rebasing to a common base
        j_noise, j_signal = pjt.rebase_traces(j_noise, j_signal)

        j_diff = dict()
        j_diff['modules'] = j_signal['modules']
        # This is broken down for readability
        s = j_signal['calls']
        n = j_noise['calls']
        j_diff['calls'] = [x for x in s if x not in n]

        pjt.write_trace_to_file('diff_trace.json', j_diff)

        self.myStatusBar.showMessage('Done diffing')


    def showAbout(self):
        QMessageBox.about(
            self,
            'About PIN Tracer',
            'Everything is better with Python and Qt :)'
            )


    def quitProgram(self):
        myApp.quit()


    ####################################################################
    # AUXILIARY
    ####################################################################
    def notYet(self):
        """
        Info is better than silently pass :)
        """
        QMessageBox.information(
            self,
            'Info',
            'This functionality is not implemented yet'
            )


    def browseFileExe(self):
        """
        Get executable to trace
        """
        filename, fltr = QtGui.QFileDialog.getOpenFileName(
            self,
            "Executable to fuzz",
            "",
            "Executables (*.exe)"
            )

        if filename:
            self.exec_name_edit.setText(filename)


    def browsePinBinary(self):
        """
        Get PIN Binary
        """
        filename, fltr = QtGui.QFileDialog.getOpenFileName(
            self,
            "PIN binary file",
            "",
            "Batch files (*.bat)"
            )

        if filename:
            self.pin_bin_location_edit.setText(filename)


    def browseFileOutput(self):
        """
        Get output file
        """
        filename, fltr = QtGui.QFileDialog.getOpenFileName(
            self,
            "Output file",
            "",
            "Text files (*.json)"
            )

        if filename:
            self.out_file_edit.setText(filename)


###################################################################################
if __name__ == '__main__':

    try:
        # Some styles possible:
        # 'windows', 'macintosh', 'plastique'
        QApplication.setStyle('plastique')
        myApp = QApplication(sys.argv)
        mainWindow = MainWindow()

        # Create the different visual components
        mainWindow.setupStatusBar()
        mainWindow.setupToolBar()
        mainWindow.setupCentralWidget()

        mainWindow.show()

        myApp.exec_()
        sys.exit(0)

    except SystemExit:
        # TODO: Some final statistics would be cool
        print "=" * 80
        print
        print "Shutting down..."
        print "Thanks for tracing with Intel PIN, "
        print "we know you have several choices."
        print "Please come back soon! :)"
        print
        print "=" * 80

    except Exception:
        print sys.exc_info()[1]


