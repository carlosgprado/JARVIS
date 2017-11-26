import idaapi


class jarvis_launcher_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Simple JARVIS Launcher"

    help = "Convenience Launcher for JARVIS"
    wanted_name = "JARVIS Launcher"
    wanted_hotkey = "Ctrl-J"

    def init(self):
        idaapi.msg("JARVIS launcher initialized\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        jarvis_loc = os.path.join('plugins', 'jarvis', 'jarvis.py')
        full_path = idaapi.idadir(jarvis_loc)
        idaapi.load_and_run_plugin(full_path, 0)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return jarvis_launcher_t()
