#!/usr/bin/env python

#Generates a callgraph of the current Ghidra program 
#@author Marion Marschalek 

from ghidra.util.task import TaskMonitor
from ghidra.program.database.symbol import SymbolManager
from ghidra.app.util.headless import HeadlessScript
import datetime
import json 
import os
import networkx as nx
from networkx.readwrite import json_graph
import pickle
import traceback

# Function gets the callees for a function, and returns location and call at a time
def get_calls(fun, fm):
    for inst in currentProgram.listing.getInstructions(fun.body, True):
        if not inst.flows:
            continue
        for op in inst.pcode:
            if op.opcode not in [op.CALL, op.CALLIND]:
                continue

            subfunc = fm.getFunctionAt(inst.flows[0])
            if subfunc:
                # return location of call and called sub function
                yield [inst.getAddress(), subfunc]
            else:
                continue
            break

# Convert graph to D3 JSON         
def convert_to_d3_format(graph, binaryname):

    # Create nodes list
    nodes = []
    node_to_index = {}
    
    for i, (node_id, node_data) in enumerate(graph.nodes(data=True)):
        node_to_index[node_id] = i
        node_entry = {
            'id': node_id,
            'index': i,
            **node_data
        }
        nodes.append(node_entry)
    
    # Create edges list
    links = []
    for source, target, edge_data in graph.edges(data=True):
        link_entry = {
            'source': node_to_index[source],
            'target': node_to_index[target],
            'source_name': source,
            'target_name': target,
            **edge_data
        }
        links.append(link_entry)
    
    # Create final structure
    graph_data = {
        'nodes': nodes,
        'links': links,
        'metadata': {
            'node_count': len(nodes),
            'edge_count': len(links),
            'binary_name': binaryname
        }
    }
    
    return graph_data

# PLUGIN MAIN
def run():

    dt = datetime.datetime.now()

    print('[*] '+str(dt)+' starting')

    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    rm = currentProgram.getReferenceManager()
    # If desired, uncomment to get the symbol table
    #sm = currentProgram.getSymbolTable()

    # Prepping a path to where to store any output, plot or pickle
    binaryname = currentProgram.getExecutablePath().split('/')[-1]
    binarypath = os.path.join(r"<GRAPHFOLDER>/graphs", binaryname)

    nxgraph = nx.DiGraph()

    # Get all the functions in the sample
    funcs = fm.getFunctions(True)  # True means iterate forward

    for func in funcs:
        body = func.getBody()

        if body:
            fname = func.getName().replace(':', '_')
            faddr = func.getEntryPoint()

            # This very line is where the node format is defined
            nxgraph.add_node(str(faddr), name=fname, address=hex(body.getMinAddress().getOffset()), size=int(body.getMaxAddress().subtract(body.getMinAddress())), called_functions=[], 
                              referenced_strings=[], libfunc=False) 
          
            # get_calls yields a two item list per callee, location and sub function address
            # need to get this information out of the disassembly to know in which order the calls happen
            for callee in get_calls(func, fm):

                # get address of called function and add edge between caller and callee
                calleeAddr = callee[1].getEntryPoint()
                nxgraph.add_edge(str(faddr), str(calleeAddr))

                # generate entry for calls list in node and append entry
                callsEntry = callee[1].getName().replace(':', '_')
                nxgraph.nodes[str(faddr)]['called_functions'].append(callsEntry)
            
        else:
            print("Function without body " + str(func))

    # Tag library functions recursively
    for func in nxgraph.nodes:
        if not "EXTERNAL" in func:
            funcnode = nxgraph.nodes[func]

            # library functions do not call back into application code
            # hence descendants of library nodes are.. more library nodes
            if funcnode['libfunc'] == True:
                descs = nx.descendants(nxgraph, func)
                for desc in descs:
                    if nxgraph.nodes[desc]['name'] not in ["main", "_start", "_entry"]:
                        nxgraph.nodes[desc]['libfunc'] = True

    # Parse for strings and add them to nodes of functions referencing them
    # Iterate through all data, including strings
    dataIter = listing.getDefinedData(True)
    for item in dataIter:

        # Filter for strings
        dataType = item.getBaseDataType().getName().lower()
        if "string" in dataType or "unicode" in dataType:

            # get all cross references to address of string
            for ref in rm.getReferencesTo(item.getMinAddress()):
                theString = item.getValue()

                if theString != None:
                        
                    theStringAddress = ref.getFromAddress()
                    sourceFunction = listing.getFunctionContaining(theStringAddress)

                    # Add string to graph, remove : to enable pydot plotting
                    if sourceFunction:
                        sourceAddr = sourceFunction.getEntryPoint()
                        nxgraph.nodes[str(sourceAddr)]['referenced_strings'].append(str(theStringAddress) + "|" + theString.replace(':', '_'))
                        
                    else:
                        # In this case we found a string thats not referenced 
                        # Action here is optional
                        pass                       

    # Stats for D3: call_count, string_count
    for func in nxgraph.nodes:
        funcnode = nxgraph.nodes[func]
        funcnode['call_count'] = len(funcnode['called_functions'])
        funcnode['string_count'] = len(funcnode['referenced_strings'])

    # This code lists all symbols present in disassembled binary, interesting but not super useful
    #smi = sm.getSymbolIterator(True)
    #for symbol in smi:
    #    print(symbol)

    # PICKLING
    #pickle.dump(nxgraph, open(binarypath + ".pk", "wb"))
    #print("[*] "+str(dt)+"Pickled " + binaryname)
	
	# DUMP JSON FOR D3
    data = convert_to_d3_format(nxgraph, binaryname)
    d3file = binarypath + ".ghidra.json"
    with open(d3file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("[*] "+str(dt)+"JSON'd " + binaryname)

    dt = datetime.datetime.now()
    print('[*] ' + str(dt) + ' done')

if __name__ == '__main__':
    run()

