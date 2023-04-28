#!/usr/bin/python
#
# Name: jarvis.py
# Description: This is the MAIN FILE for IDA's jarvis plugin
#

from idc import *
from idautils import *
from idaapi import *
import idaapi

from PyQt5.QtWidgets import QTabWidget, QVBoxLayout
from PyQt5.QtGui import QIcon

from jarvis.Config import JConfig

from jarvis.core.BinaryAnalysis import BinaryAnalysis
from jarvis.core.VulnDetection import VulnDetection
from jarvis.core.ImportExport import ImportExport
from jarvis.core.Firmware import Firmware

from jarvis.widgets.VulnDetectionWidget import VulnDetectionWidget
from jarvis.widgets.BinaryAnalysisWidget import BinaryAnalysisWidget
from jarvis.widgets.ImportExportWidget import ImportExportWidget
from jarvis.widgets.OptionsWidget import OptionsWidget
from jarvis.widgets.FirmwareWidget import FirmwareWidget

from jarvis.core.helpers.UI import install_ui_hooks

__VERSION__ = 0.8


#################################################################
class JarvisPluginForm(PluginForm):
    """
    Jarvis main window.
    Setup of core modules and widgets is performed in here.
    """

    def __init__(self):
        """
        Initialization. Dough.
        """
        super(JarvisPluginForm, self).__init__()
        self.jarvisWidgets = []
        self.config = JConfig()
        self.icon_path = self.config.icons_path
        self.tabs = None
        self.parent = None

    def showBanner(self):
        """
        Old school is cool
        """
        banner = (
                "=============================================\n"
                "= Jarvis starting...\n\n"
                )

        print(banner)

    def OnCreate(self, form):
        """
        This is called on form creation (obviously)
        """
        self.showBanner()
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(QIcon(self.icon_path + 'user-ironman.png'))

        self.setupCore()
        self.setupWidgets()
        self.setupUI()

    def setupCore(self):
        """
        Initializes all internal functionality
        """
        print("* Instantiating core modules...\n")

        self.binary_analysis = BinaryAnalysis()
        self.vuln_detection = VulnDetection()
        self.import_export = ImportExport()
        self.firmware = Firmware()

    def setupWidgets(self):
        """
        Instantiates all widgets
        """
        print("* Creating / Loading individual widgets...")

        # TODO: programmatically load the desired widgets
        # Append to the list every widget you have
        self.jarvisWidgets.append(BinaryAnalysisWidget(self))
        self.jarvisWidgets.append(VulnDetectionWidget(self))
        self.jarvisWidgets.append(ImportExportWidget(self))
        self.jarvisWidgets.append(FirmwareWidget(self))
        self.jarvisWidgets.append(OptionsWidget(self))

        self.setupJarvisForm()

    def setupJarvisForm(self):
        """
        Already initialized widgets are arranged in tabs on the main window.
        """
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)

        for widget in self.jarvisWidgets:
            self.tabs.addTab(widget, widget.icon, widget.name)

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)

        self.parent.setLayout(layout)

    def setupUI(self):
        """
        Manages the IDA UI extensions / modifications.
        NOTE: This uses some GUI functionality introduced
        in IDA 6.7
        """
        install_ui_hooks()

    def Show(self):
        """
        Overload this method to specify form options
        """
        return PluginForm.Show(self,
            ":: JARVIS ::",
            options = (
                PluginForm.WCLS_CLOSE_LATER |
                PluginForm.WOPN_RESTORE |
                PluginForm.WCLS_SAVE
                )
            )

    def OnClose(self, form):
        """
        Perform some cleanup here, if necessary
        """
        print("* JarvisPluginForm closed *")


#################################################################
class JarvisPlugin(plugin_t):
    """
    This is the skeleton plugin as seen by IDA
    """
    flags = 0
    comment = "Jarvis Plugin. Your personal IDA butler."
    help = "It saves time... and headaches."
    wanted_name = "JARVIS"
    wanted_hotkey = "Ctrl-Alt-F8"

    def init(self):
        self.icon_id = 0
        return PLUGIN_KEEP

    def run(self, arg = 0):
        f = JarvisPluginForm()
        f.Show()

    def term(self):
        msg("[*] JarvisPlugin terminated")


#################################################################
def PLUGIN_ENTRY():
    """
    Entry point for IDA
    """
    return JarvisPlugin()


#################################################################
# Usage as script (through Alt+F7)
#################################################################
def main():

    global JARVIS

    try:
        # There is an instance, reload it
        JARVIS
        JARVIS.OnClose(JARVIS)
        JARVIS = JarvisPluginForm()

    except:
        # There is no instance yet
        JARVIS = JarvisPluginForm()

    JARVIS.Show()


if __name__ == '__main__':
    main()
