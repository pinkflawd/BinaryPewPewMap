#!/usr/bin/env python3
"""
Binary Ninja Call Graph Extractor

This script extracts a call graph from a binary where:
- Nodes represent functions
- Edges represent calls and references between functions
- Node attributes include called functions, referenced functions, and referenced strings

Output: JSON file with the call graph structure
"""

import json
import binaryninja as bn

def get_string_refs_in_function(func):
    """Extract all string references within a function."""
    strings = set()
    
    # Iterate basic blocks line by line to extract referenced strings
    for bb in func.basic_blocks:
        for line in bb.disassembly_text:
            for token in line.tokens:
                if token.type == bn.InstructionTextTokenType.StringToken:
                    # Extract the actual string value
                    strings.add(token.text)
            
            # Also check data references
            for ref in bv.get_code_refs(line.address):
                if ref.function == func:
                    # Check if this references a string
                    data_var = bv.get_data_var_at(line.address)
                    if data_var and data_var.type and 'char' in str(data_var.type):
                        try:
                            string_val = bv.get_ascii_string_at(line.address, 2)
                            if string_val:
                                strings.add(string_val.value)
                        except:
                            pass
    
    return list(strings)

def extract_call_graph(bv):
    """
    Extract call graph from the binary view.
    
    Returns a dictionary with:
    - nodes: list of function nodes with attributes
    - edges: list of edges representing calls/references
    """
    
    # Graph metadata to appease D3 JS
    graph = {
        "nodes": [],
        "links": [],
        "metadata": {
            "node_count": 0,
            "edge_count": 0,
            "binary_name": bv.file.original_filename
        }
    }
    
    # Dictionary to store function to node index mapping for edge data
    func_map = {}
    index = 0
    
    # First pass: Create all nodes
    for func in bv.functions:
        func_name = func.name
        func_addr = func.start
        
        # Get called functions (outgoing calls)
        called_funcs = []
        for callee in func.callees:
            called_funcs.append(callee.name)
        
        # Get string references in this function
        string_refs = get_string_refs_in_function(func)
        
        # Get code references TODO move this to string extraction
        referenced_func = []
        for ref in bv.get_code_refs_from(func.start, func):
            referenced_func.append(hex(ref))
        
        node = {
            "id": hex(func_addr),
            "index": index,
            "name": func_name,
            "address": hex(func_addr),
            "size": func.total_bytes,
            "called_functions": called_funcs,
            "referenced_functions": referenced_func,
            "referenced_strings": string_refs,
            "call_count": len(called_funcs),
            "reference_count": len(referenced_func),
            "string_count": len(string_refs)  
        }
        
        graph["nodes"].append(node)
        func_map[func_addr] = index
        
        index += 1
    
    # Second pass: Create edges
    edge_set = set()  # To avoid duplicate edges
    
    for func in bv.functions:
        source_id = func_map[func.start]
        
        # Add edges for function calls
        for callee in func.callees:
            target_id = func_map[callee.start]
            edge_key = (source_id, target_id, "call")
            
            if edge_key not in edge_set:
                graph["links"].append({
                    "source": source_id,
                    "target": target_id,
                    "edge_type": "call",
                    "source_name": func.name,
                    "target_name": callee.name
                })
                edge_set.add(edge_key)
        
        # Add edges for code references (non-call references) TODO verify 
        for ref_site in bv.get_code_refs(func.start):
            if ref_site.function:
                target_id = func_map[ref_site.function.start]
                
                # Only add if it's not already a call edge
                if (source_id, target_id, "call") not in edge_set:
                    edge_key = (source_id, target_id, "reference")
                    
                    if edge_key not in edge_set:
                        graph["links"].append({
                            "source": source_id,
                            "target": target_id,
                            "edge_type": "reference",
                            "source_name": func.name,
                            "target_name": ref_site.function.name
                        })
                        edge_set.add(edge_key)
    
    graph["metadata"]["node_count"] = len(graph['nodes'])
    graph["metadata"]["edge_count"] = len(graph['links'])

    return graph


def main(bv):
    """Main function to run the script."""
    print("[*] Extracting call graph...")
    
    # Extract the call graph
    call_graph = extract_call_graph(bv)
    
    print(f"[+] Extracted {len(call_graph['nodes'])} nodes and {len(call_graph['links'])} edges")
    
    # Create output filename based on binary name
    output_file = bv.file.filename + ".binja.json"
    binarypath = os.path.join(r"<GRAPHFOLDER>/graphs", output_file)
    
    # Write to JSON file
    with open(binarypath, 'w') as f:
        json.dump(call_graph, f, indent=2)
    
    print(f"[+] Call graph saved to: {output_file}")
    
    # Also display some statistics
    print(f"\n[*] Statistics:")
    print(f"    Total functions: {len(call_graph['nodes'])}")
    print(f"    Total edges: {len(call_graph['links'])}")
    
    # Count edge types
    calls = sum(1 for e in call_graph['links'] if e['edge_type'] == 'call')
    refs = sum(1 for e in call_graph['links'] if e['edge_type'] == 'reference')
    print(f"    Call edges: {calls}")
    print(f"    Reference edges: {refs}")
    
    return call_graph


# For Binary Ninja plugin registration
if __name__ == "__main__":
    # When run as a script
    import sys
    if len(sys.argv) > 1:
        with bn.load(sys.argv[1]) as bv:
            if bv:
                main(bv)
            else:
                print("[-] Failed to open binary")
    else:
        print("Usage: python script.py <binary_file>")
else:
    # When run from Binary Ninja UI
    PluginCommand.register(
        "Extract Call Graph",
        "Extract call graph to JSON",
        main
    ) 