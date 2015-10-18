#
# Little module
# Process traces in JSON format
#

import json

"""
Example:

j_red = load_trace_from_file('trace-1.json')
j_green = load_trace_from_file('trace-2.json')

j_green = rebase_trace(j_green, 0x500000)
j, k = rebase_traces(j_red, j_green)
"""


def load_trace_from_file(filename):
    """
    Convenience wrapper.
    Loads a JSON serialized file to
    a python object
    @param filename: filename, dough!
    @return: the python object
    """
    with open(filename, 'r') as f:
        data = f.read()

    return json.loads(data)


def write_trace_to_file(filename, j_obj):
    """
    Convenience wrapper.
    Writes the serialized JSON object
    to a file on disk
    @param filename: filename, dough!
    @param j_obj: the JSON object
    @return: None
    """
    with open(filename, 'w') as f:
        f.write(json.dumps(j_obj))


def rebase_trace(j_obj, new_base_addr):
    """
    Processes the trace (JSON object) and
    rebases all calls to a new base adress
    @param j_obj: a python/JSON object
    @param new_base_addr: address to rebase
    @return: new python/JSON object
    """
    new_j_obj = j_obj

    mod = get_traced_module(j_obj)
    mod_name = mod['name']
    old_base_addr = mod['begin']
    old_end_addr = mod['end']

    delta = new_base_addr - old_base_addr

    # Change the addresse in the corresponding
    # module entry
    for m in new_j_obj['modules']:
        if m['name'] == mod_name:
            m['begin'] += delta
            m['end'] += delta

    for c in new_j_obj['calls']:
        # Always check if the address correspond to
        # the rebased module. Not all calls are
        # inter-modular :)
        if c['u'] >= old_base_addr and c['u'] <= old_end_addr:
            c['u'] += delta

        if c['v'] >= old_base_addr and c['v'] <= old_end_addr:
            c['v'] += delta

    return new_j_obj


def rebase_traces(j1, j2):
    """
    Finds a common base address to rebase both traces.
    This is important if we need to compare executions,
    for example while doing differential tracing
    @param: j1, j2: JSON objects
    @return: tuple(j1', j2')
    """
    base1 = get_traced_module(j1)['begin']
    base2 = get_traced_module(j2)['begin']

    if base1 == base2:
        print "[*] NO ASLR, no need to rebase traces."
        return j1, j2

    # Let's rebase the trace with the lower base
    # Actually not relevant but this way I only
    # deal with positive offsets
    if base1 > base2:
        j2 = rebase_trace(j2, base1)

    else:
        j1 = rebase_trace(j1, base2)

    return j1, j2


def get_traced_module(j_obj, debug = False):
    """
    Returns information about the module
    traced, that is, not excluded at trace time
    @param j_obj: python/JSON object repr. trace
    @param debug: print console info
    @return: an module object
    """
    modules = j_obj['modules']
    # This is a list of dictionaries
    # in Python speech
    for mod in modules:
        if mod['excluded']:
            continue

        else:
            if debug:
                print "Traced module"
                print "-------------"
                print "Name:    %s" % mod['name']
                print "Begin:   0x%08x" % mod['begin']
                print "End:     0x%08x" % mod['end']
                print

            return mod

    return None
