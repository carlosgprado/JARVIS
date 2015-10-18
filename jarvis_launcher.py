import idaapi


class jarvis_launcher_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Simple JARVIS Launcher"

    help = "Convenience Launcher for JARVIS"
    wanted_name = "JARVIS Launcher"
    wanted_hotkey = "Alt-J"

    def init(self):
        idaapi.msg("JARVIS launcher initialized\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.load_and_run_plugin('jarvis\jarvis.py', 0)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return jarvis_launcher_t()
