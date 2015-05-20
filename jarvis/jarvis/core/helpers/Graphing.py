#!/usr/bin/python
#
# Name: Graphing.py
# Description: Routines to aid with creation of custom graphs and their manipulation.
#

from idc import *
from idaapi import *
from idautils import *

from collections import defaultdict

from InfoUI import InfoUI
import Misc as misc

try:
    import networkx as nx

except:
    print "[!] Could not import NetworkX"
    print "[!] Some functionality will not be available"

###################################################################################################
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
        idNode = dict() # { node_ea : node_id }

        for node_ea in self.graph.keys():
            # First, add all nodes and populate the idNode list
            idNode[node_ea] = self.AddNode(node_ea)

        for paths in self.graph.values():
            # Add nodes without children (only ingress)
            for node_ea in paths:
                if node_ea not in idNode:
                    idNode[node_ea] = self.AddNode(node_ea)

        for node_ea, child_set in self.graph.iteritems():
            # Link the node with parents and children
            # These 'children' elements are *all* references from the node,
            # not just the ones belonging to the connected graph.
            for child in child_set:
                try:
                    self.AddEdge(idNode[node_ea], idNode[child])
                except:
                    continue

        # Calculate a handy reverse dictionary { node_id: node_ea }
        self.AddrNode = dict()
        for ea, id in idNode.iteritems():
            self.AddrNode[id] = ea

        return True


    def DisasmAround(self, node_id):
        """
        Writes the function disassembly
        (around interesting function calls)
        """
        interesting_fn_names = list()
        node_ea = self.AddrNode[node_id]

        # We are interested in the function calls from the node, which
        # are actually part of the connected graph :)
        for x in self.graph[node_ea]:
            if x in self.graph.keys(): # node list
                interesting_fn_names.append(GetFunctionName(x))

        position = 0
        fi = FuncItems(node_ea)
        f_items = list(fi) # generator -> list

        NodeText = "[ %s ]\n\n" % GetFunctionName(node_ea)

        for ins in f_items:
            # Find call to interesting function and
            # slice around the call in disasm
            disasm = GetDisasm(ins)
            if is_call_insn(ins):
                for name in interesting_fn_names:
                    if name in disasm:
                        disasm_slice = f_items[position - 3 : position + 3]
                        for instr in disasm_slice:
                            NodeText += "%s\n" % GetDisasm(instr)

                        NodeText += "[...]\n"

            position += 1

        return NodeText


    def OnGetText(self, node_id):
        return (GetFunctionName(self.AddrNode[node_id]), 0x800000)


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
            print "[debug] Failed to add popup menu item for GraphView"

        return True


###################################################################################################
class FunctionGraph():

    def __init__(self):
        """
        It leverages FlowChart API in order to calculate
        some graph properties (function granularity)
        """
        pass


    def connect_graph(self, u, v, co):
        """
        Calculates connections between functions
        :return: a subgraph in a format suitable for GraphViewer
        g_connect[node_ea] = set([child_1, child_2, ...])
        """
        FG = BinaryGraph()

        paths = nx.all_simple_paths(FG, source = u, target = v, cutoff = co)

        paths_l = list(paths)

        g_connect = defaultdict(set)
        for path in paths_l:
            # path: [node_1, node_2, node_3, ...]
            node_ea = path[0]

            for n in path[1:]:
                g_connect[node_ea].add(n)
                node_ea = n

        return g_connect




###########################################################
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

        bb_dict = defaultdict(list)     # Dict of BasicBlock objects

        for bb in f:
            for child in bb.succs():
                bb_dict[bb.startEA].append(child.startEA)

        return bb_dict


    def _graph_to_networkx(self, bb_dict):
        """
        Accepts a bb_dict (see _get_function_graph) and converts
        this to a NetworkX format
        :param bb_dict: dictionary { block_ea: [branch1_ea, branch2_ea], ... }
        :return: NetworkX graph
        """
        DG = nx.DiGraph()

        for node, children in bb_dict.iteritems():
            for child in children:
                DG.add_edge(node, child)

        return DG


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
        G = self._graph_to_networkx(self.bb_graph)

        # Read this information from InfoUI
        try:
            bb_start = InfoUI.bb_start
            bb_end = InfoUI.bb_end

        except AttributeError:
            print '[!] find_connected_paths: check your marked start and end basic blocks!'
            return None

        # Sanity check.
        # Basic blocks within current function?
        bbl = [bb.startEA for bb in self.f]

        # bbl contains startEA's. However, we may have clicked
        # *somewhere* within the basic block :-/
        _bb_start = self.get_block_from_ea(bb_start).startEA
        _bb_end = self.get_block_from_ea(bb_end).startEA

        if _bb_start in bbl and _bb_end in bbl:
            # TODO: Select cutoff in OPTIONS widget at runtime
            paths = nx.all_simple_paths(G, source = _bb_start, target = _bb_end, cutoff = co)
            return paths

        else:
            print '[!] find_connected_paths: check your marked start and end basic blocks!'
            return None


    def get_block_from_ea(self, ea):
        """
        It returns the idaapi.BasicBlock
        containing ea or None
        """
        for bb in self.f:
            # Remember that bb.endEA is bb.startEA of the next one!
            if ea >= bb.startEA and ea < bb.endEA:
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
        e = bb.endEA
        tail = DecodePreviousInstruction(e)

        return tail


###########################################################
# Auxiliary stuff
###########################################################
def BinaryGraph():
    """
    This calculates a graph of the whole binary.
    :return: a graph in NetworkX format
    """
    FG = nx.DiGraph()

    for f_ea in Functions():
        # TODO: Test a bit more the restrictions regarding
        # the types of XRefs
        for xref in XrefsTo(f_ea, 1):
            (s, e) = misc.function_boundaries(xref.frm)
            if s:
                FG.add_edge(s, f_ea)

    return FG


def cg_to_networkx(cg):
    """
    Converts a connect graph to a format
    suitable for using with NetworkX (DiGraph)

    Remember, connect graph format looks like this:
    { node_ea : {
            'children': [child1_ea, child2_ea...],
            'parents': [parent1_ea, parent2_ea]
            },
    ...}
    """
    DG = nx.DiGraph()

    # TODO: check this algorithm with loops
    for node_ea in cg:
        for child_ea in cg[node_ea]['children']:
            DG.add_edge(node_ea, child_ea)

    return DG


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
    DG = nx.DiGraph()
    for u, v in edge_list:
        DG.add_node(u, label = u)
        DG.add_node(v, label = v)
        DG.add_edge(u, v)

    nx.write_graphml(DG, filename)

    return True