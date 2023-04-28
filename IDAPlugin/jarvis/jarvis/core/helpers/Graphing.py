#!/usr/bin/python
#
# Name: Graphing.py
# Description: Routines regarding creation of custom graphs
#

from idc import *
from idaapi import *
from idautils import *

from collections import defaultdict

from .InfoUI import InfoUI
from . import Misc as misc

try:
    import networkx as nx

except:
    print("[!] Could not import NetworkX")
    print("[!] Some functionality will not be available")


class ConnectGraph(GraphViewer):
    def __init__(self, graph):
        """
        This is an auxiliary GUI element.
        The heavy lifting is done somewhere else, this just draws :)
        :param graph: g_connect[node_ea] = set([child_1, child_2, ...])
        """
        super(ConnectGraph, self).__init__("Connect Graph")
        self.graph = graph

    def OnRefresh(self):
        """
        This is the main 'drawing' routine.
        """
        # TODO: this algorithm is a bit clumsy. Get back to it.

        self.Clear()
        id_node = dict()  # { node_ea : node_id }

        for node_ea in list(self.graph.keys()):
            # First, add all nodes and populate the id_node list
            id_node[node_ea] = self.AddNode(node_ea)

        for paths in list(self.graph.values()):
            # Add nodes without children (only ingress)
            for node_ea in paths:
                if node_ea not in id_node:
                    id_node[node_ea] = self.AddNode(node_ea)

        for node_ea, child_set in self.graph.items():
            # Link the node with parents and children
            # These 'children' elements are *all* references from the node,
            # not just the ones belonging to the connected graph.
            for child in child_set:
                try:
                    self.AddEdge(id_node[node_ea], id_node[child])
                except:
                    continue

        # Calculate a handy reverse dictionary { node_id: node_ea }
        self.AddrNode = dict()
        for ea, id in id_node.items():
            self.AddrNode[id] = ea

        return True

    def OnGetText(self, node_id):
        return get_func_name(self.AddrNode[node_id]), 0x800000

    def OnDblClick(self, node_id):
        """
        Double clicking on a node, jump to it in disassembly
        """
        Jump(self.AddrNode[node_id])
        return True

    def OnSelect(self, node_id):
        return True

    def OnHint(self, node_id):
        return "%x" % self.AddrNode[node_id]

    def OnClick(self, node_id):
        return True

    def OnCommand(self, cmd_id):
        """
        Triggered when a menu command is selected through the menu of hotkey
        @return: None
        """
        if cmd_id == self.cmd_close:
            self.Close()
            return

    def Show(self):
        if not GraphViewer.Show(self):
            return False

        # Add some handy commands to the graph view :)
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            print("[debug] Failed to add popup menu item for GraphView")

        return True


class FunctionGraph():
    def __init__(self):
        """
        It leverages FlowChart API in order to calculate
        some graph properties (function granularity)
        """
        print("Instantiating a FunctionGraph object...")

    def connect_graph(self, u, v, co):
        """
        Calculates connections between functions
        :return: a subgraph in a format suitable for GraphViewer
        g_connect[node_ea] = set([child_1, child_2, ...])
        """
        FG = binary_graph()
        paths = nx.all_simple_paths(FG, source = u, target = v, cutoff = co)

        g_connect = defaultdict(set)

        for path in paths:
            # path: [node_1, node_2, node_3, ...]
            node_ea = path[0]

            for n in path[1:]:
                g_connect[node_ea].add(n)
                node_ea = n

        return g_connect


class BlockGraph():
    def __init__(self, f_ea):

        self.f_ea = f_ea
        self.f = FlowChart(get_func(f_ea), None, FC_PREDS)
        self.bb_graph = self._get_function_graph(self.f)

    def _get_function_graph(self, f):
        """
        It creates a graph of basic blocks and their children.

        @type ea: address
        @param ea: address anywhere within the analyzed function.

        @rtype: dictionary
        @return: dictionary { block_ea: [branch1_ea, branch2_ea], ... }
        """

        bb_dict = defaultdict(list)  # Dict of BasicBlock objects

        for bb in f:
            for child in bb.succs():
                bb_dict[bb.start_ea].append(child.start_ea)

        return bb_dict

    def _graph_to_networkx(self, bb_dict):
        """
        Accepts a bb_dict (see _get_function_graph) and converts
        this to a NetworkX format
        :param bb_dict: dictionary { block_ea: [branch1_ea, branch2_ea], ... }
        :return: NetworkX graph
        """
        dg = nx.DiGraph()

        for node, children in bb_dict.items():
            for child in children:
                dg.add_edge(node, child)

        return dg

    def find_connected_paths(self, co):
        """
        Do yourself a favor and let the professionals
        do the algorithm thing :)
        NOTE: the cutoff parameter in nx.all_simple_paths
        serves two purposes:
        1. reduce the chances of CPU melting (algo is O(n!))
        2. nobody will inspect (manually) monstruous paths
        :param co: The cutoff value
        :return: generator of lists or None
        """
        g = self._graph_to_networkx(self.bb_graph)

        # Read this information from InfoUI
        try:
            bb_start = InfoUI.bb_start
            bb_end = InfoUI.bb_end

        except AttributeError:
            print('[!] find_connected_paths: check your marked start and end basic blocks!')
            return None

        # Sanity check.
        # Basic blocks within current function?
        bbl = [bb.start_ea for bb in self.f]

        # bbl contains startEA's. However, we may have clicked
        # *somewhere* within the basic block :-/
        _bb_start = self.get_block_from_ea(bb_start).start_ea
        _bb_end = self.get_block_from_ea(bb_end).start_ea

        if _bb_start in bbl and _bb_end in bbl:
            # TODO: Select cutoff in OPTIONS widget at runtime
            paths = nx.all_simple_paths(g, source = _bb_start, target = _bb_end, cutoff = co)
            return paths

        else:
            print('[!] find_connected_paths: check your marked start and end basic blocks!')
            return None

    def get_block_from_ea(self, ea):
        """
        It returns the idaapi.BasicBlock
        containing ea or None
        """
        for bb in self.f:
            # Remember that bb.end_ea is bb.start_ea of the next one!
            if ea >= bb.start_ea and ea < bb.end_ea:
                return bb

        return None

    def get_block_preds(self, ea):
        """
        NOTE: Somehow preds() does not work,
        so I have to implement my own one :'(
        UPDATE: To get predecessors, FlowChart must be
        called with flags FC_PREDS o.O
        @returns: a list of blocks predecessors
        """
        current_bb = self.get_block_from_ea(ea)

        return list(current_bb.preds())

    def get_block_tail_ins(self, ea):
        """
        Auxiliary
        It returns the last instruction
        within a basic block
        """
        bb = self.get_block_from_ea(ea)
        # This is actually the first instruction
        # of the successor basic block
        e = bb.end_ea
        tail = DecodePreviousInstruction(e)

        return tail


###########################################################
# Auxiliary stuff
###########################################################
def binary_graph():
    """
    This calculates a graph of the whole binary.
    :return: a *DiGraph* in NetworkX format
    """
    fg = nx.DiGraph()

    for f_ea in Functions():
        for xref in XrefsTo(f_ea, True):
            # NOTE: only code xrefs (that is, call sub_xxx or
            # alike but not data refs, mov [eax], sub_xxx
            if not xref.iscode:
                continue

            (s, e) = misc.function_boundaries(xref.frm)
            if s:
                fg.add_edge(s, f_ea)

    return fg


def cg_to_networkx(cg):
    """
    Converts a connect graph to a format
    suitable for using with NetworkX (Graph)

    Remember, connect graph format looks like this:
    { node_ea : {
            'children': [child1_ea, child2_ea...],
            'parents': [parent1_ea, parent2_ea]
            },
    ...}
    """
    dg = nx.DiGraph()

    # TODO: check this algorithm with loops
    for node_ea in cg:
        for child_ea in cg[node_ea]['children']:
            dg.add_edge(node_ea, child_ea)

    return dg


def cg_shortest_path(cg, u, v):
    """
    Returns the shortest path in a
    connection graph (uses NetworkX)
    @return: node list or None on error
    """
    dg = cg_to_networkx(cg)
    try:
        sp = nx.shortest_path(dg, source = u, target = v)

    except:
        # nx.NetworkXNoPath or alike
        return None

    return sp


def write_to_graphml(edge_list, filename):
    """
    :param filename: string
    :param edge_list: a list of edges [(u, v),...]
    :return: None
    """
    dg = nx.DiGraph()
    for u, v in edge_list:
        dg.add_node(u, label = u)
        dg.add_node(v, label = v)
        dg.add_edge(u, v)

    nx.write_graphml(dg, filename)

    return True
