#!/usr/bin/env python
"""
IDAPython script to extract binary call graphs for D3.js visualization.

This script creates a NetworkX graph where:
- Nodes represent functions
- Edges represent function calls/references
- Node attributes include referenced strings and functions
- Output is JSON format compatible with D3.js

Usage: Run this script in IDA Pro with IDAPython
"""

import ida_funcs
import ida_xref
import ida_name
import ida_nalt
import ida_bytes
import ida_idaapi
import ida_ua
import ida_segment
import idautils
import ida_kernwin
import idc
import json
import networkx as nx
from collections import defaultdict

def get_function_name(ea):
    """Get the name of a function at given address."""
    name = ida_name.get_name(ea)
    if not name:
        name = f"sub_{ea:X}"
    return name

def get_string_at_address(ea):
    """Extract string at given address if it exists."""
    flags = ida_bytes.get_flags(ea)
    
    if ida_bytes.is_strlit(flags):    
        string_type = ida_nalt.get_str_type(ea)
        string_len = ida_bytes.get_max_strlit_length(ea, string_type, ida_bytes.ALOPT_IGNHEADS | ida_bytes.ALOPT_IGNCLT)

        string_content = ida_bytes.get_strlit_contents(ea, string_len, string_type)
        if string_content:
            try:
                return string_content.decode('utf-8', errors='ignore')
            except:
                return str(string_content)
    return None

def analyze_function_references(func_ea):
    """
    Analyze a function to find:
    - Called functions
    - Referenced strings
    - Other referenced functions (not just calls)
    """
    called_functions = set()
    referenced_functions = set()
    referenced_strings = set()
    
    # Get function boundaries
    func = ida_funcs.get_func(func_ea)
    if not func:
        return called_functions, referenced_functions, referenced_strings
    
    # Iterate through all addresses in the function
    current_ea = func.start_ea
    while current_ea < func.end_ea:
        # Get all cross-references from this address
        for xref in idautils.XrefsFrom(current_ea):
            target_ea = xref.to
            
            # Check if target is a function
            target_func = ida_funcs.get_func(target_ea)
            if target_func:
                target_name = get_function_name(target_func.start_ea)
                
                # Distinguish between calls and other references
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:  # Call near/far
                    called_functions.add((target_func.start_ea, target_name))
                else:
                    referenced_functions.add((target_func.start_ea, target_name))
            else:
                # Check if target is a string
                string_content = get_string_at_address(target_ea)
                if string_content:
                    referenced_strings.add(string_content)
        
        # Move to next instruction
        next_ea = ida_bytes.next_head(current_ea, func.end_ea)
        if next_ea == ida_idaapi.BADADDR or next_ea <= current_ea:
            break
        current_ea = next_ea
    
    return called_functions, referenced_functions, referenced_strings

def create_call_graph():
    """Create NetworkX graph from binary analysis."""
    G = nx.DiGraph()
    
    print("Starting call graph extraction...")
    
    # Get all functions in the binary
    function_list = []
    for func_ea in idautils.Functions():
        func_name = get_function_name(func_ea)
        function_list.append((func_ea, func_name))
    
    print(f"Found {len(function_list)} functions")
    
    # Process each function
    for i, (func_ea, func_name) in enumerate(function_list):
        if i % 50 == 0:
            print(f"Processing function {i+1}/{len(function_list)}: {func_name}")
        
        # Analyze function references
        called_funcs, ref_funcs, ref_strings = analyze_function_references(func_ea)
        
        # Add node with attributes
        node_attrs = {
            'name': func_name,
            'address': hex(func_ea),
            'called_functions': [name for _, name in called_funcs],
            'referenced_functions': [name for _, name in ref_funcs],
            'referenced_strings': list(ref_strings)[:20],  # Limit to first 20 strings
            'string_count': len(ref_strings),
            'call_count': len(called_funcs),
            'reference_count': len(ref_funcs)
        }
        
        G.add_node(func_name, **node_attrs)
        
        # Add edges for function calls
        for target_ea, target_name in called_funcs:
            G.add_edge(func_name, target_name, edge_type='call')
        
        # Add edges for function references (with different type)
        for target_ea, target_name in ref_funcs:
            G.add_edge(func_name, target_name, edge_type='reference')
    
    return G

def convert_to_d3_format(G):
    """Convert NetworkX graph to D3.js compatible JSON format."""
    # Create nodes list
    nodes = []
    node_to_index = {}
    
    for i, (node_id, node_data) in enumerate(G.nodes(data=True)):
        node_to_index[node_id] = i
        node_entry = {
            'id': node_id,
            'index': i,
            **node_data
        }
        nodes.append(node_entry)
    
    # Create edges list
    links = []
    for source, target, edge_data in G.edges(data=True):
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
            'binary_name': ida_nalt.get_root_filename()
        }
    }
    
    return graph_data

def export_graph(filename=None):
    """Main function to extract and export the call graph."""
    if not filename:
        binary_name = ida_nalt.get_root_filename()
        filename = f"{binary_name}.ida.json"
        binarypath = os.path.join(r"<GRAPHFOLDER>/graphs", filename)
    
    print("="*50)
    print("IDA Pro Call Graph Extractor")
    print("="*50)
    
    # Create the graph
    G = create_call_graph()
    
    print(f"\nGraph Statistics:")
    print(f"- Nodes (functions): {G.number_of_nodes()}")
    print(f"- Edges (calls/refs): {G.number_of_edges()}")
    print(f"- Connected components: {nx.number_weakly_connected_components(G)}")
    
    # Convert to D3 format
    print("\nConverting to D3.js format...")
    d3_data = convert_to_d3_format(G)
    
    # Export to JSON
    try:
        with open(binarypath, 'w', encoding='utf-8') as f:
            json.dump(d3_data, f, indent=2, ensure_ascii=False)
        print(f"\nCall graph exported successfully to: {filename}")
        
        # Print some sample data
        print(f"\nSample data preview:")
        print(f"- First node: {d3_data['nodes'][0]['name']}")
        print(f"- Node attributes: {list(d3_data['nodes'][0].keys())}")
        if d3_data['links']:
            print(f"- First edge: {d3_data['links'][0]['source_name']} -> {d3_data['links'][0]['target_name']}")
        
    except Exception as e:
        print(f"Error writing to file: {e}")
        return None
    
    return d3_data

def print_graph_stats(G):
    """Print detailed statistics about the graph."""
    print("\nDetailed Graph Statistics:")
    print("-" * 30)
    
    # Basic stats
    print(f"Total functions: {G.number_of_nodes()}")
    print(f"Total edges: {G.number_of_edges()}")
    
    # Node degree statistics
    in_degrees = [G.in_degree(n) for n in G.nodes()]
    out_degrees = [G.out_degree(n) for n in G.nodes()]
    
    print(f"Average in-degree: {sum(in_degrees)/len(in_degrees):.2f}")
    print(f"Average out-degree: {sum(out_degrees)/len(out_degrees):.2f}")
    
    # Most connected functions
    most_called = sorted(G.nodes(), key=lambda x: G.in_degree(x), reverse=True)[:5]
    most_calling = sorted(G.nodes(), key=lambda x: G.out_degree(x), reverse=True)[:5]
    
    print(f"\nMost called functions:")
    for func in most_called:
        print(f"  {func}: {G.in_degree(func)} incoming calls")
    
    print(f"\nFunctions making most calls:")
    for func in most_calling:
        print(f"  {func}: {G.out_degree(func)} outgoing calls")

# Main execution
if __name__ == "__main__":
    # Check if running in IDA Pro

    ida_kernwin.get_kernel_version()
    print("Running in IDA Pro environment")
    
    # Export the graph
    graph_data = export_graph()
    
    if graph_data:
        print("\n" + "="*50)
        print("Call graph extraction completed successfully!")
        print("You can now use the generated JSON file with D3.js")
        print("="*50)
        
    