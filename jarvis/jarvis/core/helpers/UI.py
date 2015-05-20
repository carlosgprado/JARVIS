#!/usr/bin/python
#
# Name: UI.py
# Description: Extending / Modifying IDA's UI
#

from idc import *
from idaapi import *
from idautils import *

from InfoUI import InfoUI


hooks = None

class InitBBHandler(action_handler_t):
    """
    This is a handler class.
    Connects the Action with real code
    """
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        InfoUI.bb_start = here()
        print "UI: bb_start %x" % InfoUI.bb_start
        return 1

    def update(self, ctx):
        return AST_ENABLE_FOR_FORM if ctx.form_type == BWN_DISASM else AST_DISABLE_FOR_FORM


class FinalBBHandler(action_handler_t):
    """
    This is a handler class.
    Connects the Action with real code
    """
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        InfoUI.bb_end = here()
        print "UI: bb_end %x" % InfoUI.bb_end
        return 1

    def update(self, ctx):
        return AST_ENABLE_FOR_FORM if ctx.form_type == BWN_DISASM else AST_DISABLE_FOR_FORM


class InitialFuncHandler(action_handler_t):
    """
    This is a handler class.
    Connects the Action with real code
    """
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        # Thx to Arnaud :)
        idx_l = list(ctx.chooser_selection)
        if len(idx_l) > 1:
            print "UI: multiple selection not allowed!"
            return 1

        f = getn_func(idx_l[0] - 1)
        InfoUI.function_orig_ea = f.startEA
        print "UI: func_start %x" % InfoUI.function_orig_ea
        return 1

    def update(self, ctx):
        return AST_ENABLE_FOR_FORM if ctx.form_type == BWN_FUNCS else AST_DISABLE_FOR_FORM


class FinalFuncHandler(action_handler_t):
    """
    This is a handler class.
    Connects the Action with real code
    """
    def __init__(self):
        action_handler_t.__init__(self)

    def activate(self, ctx):
        idx_l = list(ctx.chooser_selection)
        if len(idx_l) > 1:
            print "UI: multiple selection not allowed!"
            return 1

        f = getn_func(idx_l[0] - 1)
        InfoUI.function_dest_ea = f.startEA
        print "UI: func_end %x" % InfoUI.function_dest_ea
        return 1

    def update(self, ctx):
        return AST_ENABLE_FOR_FORM if ctx.form_type == BWN_FUNCS else AST_DISABLE_FOR_FORM



class Hooks(UI_Hooks):
    """
    Attach the action to a context menu after
    it has been created
    """
    def finish_populating_tform_popup(self, form, popup):
        # Insert the action once the context menu
        # has been populated.
        # Submenu Others
        if get_tform_type(form) == BWN_DISASM:
            attach_action_to_popup(form, popup, 'bb:initial', 'JARVIS/')
            attach_action_to_popup(form, popup, 'bb:final', 'JARVIS/')

        elif get_tform_type(form) == BWN_FUNCS:
            attach_action_to_popup(form, popup, 'func:initial', 'JARVIS/')
            attach_action_to_popup(form, popup, 'func:final', 'JARVIS/')



def install_ui_hooks():
    """
    Do it faggot!
    @returns: None
    """
    global hooks

    initial_desc = action_desc_t(
        'bb:initial',               # Unique ID
        'Initial basic block',      # Action text
        InitBBHandler(),            # Action handler
        None,                       # Optional: shortcut
        'Sets initial basic block', # Optional: tooltip (menus, toolbars)
        199                         # Optional: icon (menus, toolbars)
    )

    final_desc = action_desc_t(
        'bb:final',                 # Unique ID
        'Final basic block',        # Action text
        FinalBBHandler(),           # Action handler
        None,                       # Optional: shortcut
        'Sets final basic block',   # Optional: tooltip (menus, toolbars)
        198                         # Optional: icon (menus, toolbars)
    )

    init_func_desc = action_desc_t(
        'func:initial',             # Unique ID
        'Initial function',         # Action text
        InitialFuncHandler(),       # Action handler
        None,                       # Optional: shortcut
        'Sets initial function',    # Optional: tooltip (menus, toolbars)
        197                         # Optional: icon (menus, toolbars)
    )

    final_func_desc = action_desc_t(
        'func:final',               # Unique ID
        'Final function',           # Action text
        FinalFuncHandler(),         # Action handler
        None,                       # Optional: shortcut
        'Sets final function',      # Optional: tooltip (menus, toolbars)
        195                         # Optional: icon (menus, toolbars)
    )


    # Register it (it does not appear in GUI yet)
    register_action(initial_desc)
    register_action(final_desc)
    register_action(init_func_desc)
    register_action(final_func_desc)

    print 'UI: Actions registered...'

    hooks = Hooks()
    if hooks.hook():
        print 'UI: Hook installed successfully'

