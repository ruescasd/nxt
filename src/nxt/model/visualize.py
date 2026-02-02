#!/usr/bin/env python3
"""
Interactive Pyvis visualization for the SecureVote threat model.

Generates an interactive HTML file that can be opened in a browser
to explore the threat model graph.
"""

import argparse
from pathlib import Path

from pyvis.network import Network

from nxt.model import model as threat_model
from nxt.schema.types import EdgeType


# Color scheme for node types
NODE_COLORS = {
    "property": "#4CAF50",    # Green - security properties
    "attack": "#F44336",      # Red - attacks
    "pattern": "#FF9800",     # Orange - attack patterns
    "mitigation": "#2196F3",  # Blue - mitigations
    "context": "#9C27B0",     # Purple - contexts
}

# Node shapes
NODE_SHAPES = {
    "property": "diamond",
    "attack": "triangle",
    "pattern": "triangleDown",
    "mitigation": "square",
    "context": "dot",
}

# Edge colors by type
EDGE_COLORS = {
    EdgeType.REFINES: "#666666",      # Gray
    EdgeType.TARGETS: "#F44336",       # Red
    EdgeType.ACHIEVES: "#FF5722",      # Deep Orange
    EdgeType.REQUIRES: "#795548",      # Brown
    EdgeType.VARIANT_OF: "#607D8B",    # Blue Gray
    EdgeType.MITIGATES: "#2196F3",     # Blue
    EdgeType.OCCURS_IN: "#9C27B0",     # Purple
}


def _inject_focus_mode_js(html_path: str, G) -> None:
    """
    Inject custom JavaScript for directional transitive reachability.
    
    When a node is clicked:
    - Follow outgoing edges transitively (forward reachability)
    - Follow incoming edges transitively (backward reachability)
    - But never reverse direction mid-traversal
    - Highlight reachable nodes, gray out unreachable ones
    """
    import json
    
    # Build adjacency lists for JavaScript
    out_edges = {}  # node -> list of successor nodes
    in_edges = {}   # node -> list of predecessor nodes
    
    for node in G.nodes():
        out_edges[node] = list(G.successors(node))
        in_edges[node] = list(G.predecessors(node))
    
    # Store original node colors
    node_colors = {}
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_colors[node_id] = NODE_COLORS.get(node_type, "#888888")
    
    # Build node labels and descriptions for search and display
    node_labels = {}
    node_descriptions = {}
    for node_id, data in G.nodes(data=True):
        node_obj = data.get("node")
        node_type = data.get("node_type", "unknown")
        if node_type == "property":
            node_labels[node_id] = node_obj.id
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "attack":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "pattern":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "mitigation":
            node_labels[node_id] = node_obj.name
            node_descriptions[node_id] = node_obj.description or ""
        elif node_type == "context":
            node_labels[node_id] = f"{node_obj.id}: {node_obj.name}"
            node_descriptions[node_id] = node_obj.name or ""
        else:
            node_labels[node_id] = str(node_id)
            node_descriptions[node_id] = ""
    
    js_code = f'''
<style>
html, body {{
    margin: 0;
    padding: 0;
    height: 100%;
    overflow: hidden;
}}
#mainContainer {{
    display: flex;
    height: 100vh;
    width: 100vw;
}}
#sidePanel {{
    width: 280px;
    min-width: 280px;
    height: 100%;
    background: #f8f9fa;
    border-right: 1px solid #dee2e6;
    box-shadow: 2px 0 10px rgba(0,0,0,0.1);
    z-index: 1000;
    font-family: Arial, sans-serif;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    box-sizing: border-box;
}}
#sidePanel h3 {{
    margin: 0;
    padding: 15px;
    background: #343a40;
    color: white;
    font-size: 16px;
}}
#sidePanel .section {{
    padding: 15px;
    border-bottom: 1px solid #dee2e6;
}}
#sidePanel .section-title {{
    font-weight: bold;
    margin-bottom: 10px;
    color: #495057;
}}
#searchInput {{
    width: 100%;
    padding: 8px 10px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    font-size: 13px;
    box-sizing: border-box;
}}
#searchInput:focus {{
    outline: none;
    border-color: #80bdff;
    box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
}}
#searchResults {{
    max-height: 200px;
    overflow-y: auto;
    margin-top: 8px;
    border: 1px solid #dee2e6;
    border-radius: 4px;
    background: white;
    display: none;
}}
#searchResults.active {{
    display: block;
}}
.search-item {{
    padding: 8px 10px;
    cursor: pointer;
    border-bottom: 1px solid #eee;
}}
.search-item:last-child {{
    border-bottom: none;
}}
.search-item:hover {{
    background: #e9ecef;
}}
.search-item .node-type {{
    font-size: 10px;
    color: #6c757d;
    text-transform: uppercase;
}}
#sidePanel label {{
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
}}
#sidePanel input[type="checkbox"] {{
    width: 16px;
    height: 16px;
}}
#focusStatus {{
    padding: 15px;
    background: #e9ecef;
    color: #495057;
}}
#focusStatus.active {{
    background: #d4edda;
    color: #155724;
}}
#nodeDetails {{
    flex: 1;
    padding: 15px;
    overflow-y: auto;
    border-top: 1px solid #dee2e6;
    display: none;
}}
#nodeDetails.active {{
    display: block;
}}
#nodeDetails .node-title {{
    font-weight: bold;
    font-size: 14px;
    margin-bottom: 5px;
    color: #212529;
}}
#nodeDetails .node-type-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    text-transform: uppercase;
    margin-bottom: 10px;
    color: white;
}}
#nodeDetails .node-type-badge.property {{ background: #4CAF50; }}
#nodeDetails .node-type-badge.attack {{ background: #F44336; }}
#nodeDetails .node-type-badge.pattern {{ background: #FF9800; }}
#nodeDetails .node-type-badge.mitigation {{ background: #2196F3; }}
#nodeDetails .node-type-badge.context {{ background: #9C27B0; }}
#nodeDetails .node-description {{
    font-size: 12px;
    line-height: 1.5;
    color: #495057;
}}
.hint {{
    color: #6c757d;
    font-size: 11px;
    margin-top: 8px;
}}
#graphContainer {{
    flex: 1;
    height: 100%;
    position: relative;
}}
</style>
<script type="text/javascript">
document.addEventListener('DOMContentLoaded', function() {{
    // Wrap existing content in flex container
    var mynetwork = document.getElementById('mynetwork');
    
    // Create main container
    var mainContainer = document.createElement('div');
    mainContainer.id = 'mainContainer';
    
    // Create side panel
    var sidePanel = document.createElement('div');
    sidePanel.id = 'sidePanel';
    sidePanel.innerHTML = `
        <h3>Threat Model Explorer</h3>
        <div class="section">
            <div class="section-title">Search Nodes</div>
            <input type="text" id="searchInput" placeholder="Type to search...">
            <div id="searchResults"></div>
        </div>
        <div class="section">
            <div class="section-title">Focus Options</div>
            <label>
                <input type="checkbox" id="hideUnreachable">
                <span>Hide unreachable nodes</span>
            </label>
            <div class="hint">Click node to focus on reachable subgraph.<br>Shift+Click toggles hide mode.</div>
        </div>
        <div id="focusStatus">Click a node to focus</div>
        <div id="nodeDetails">
            <div class="node-title" id="nodeTitle"></div>
            <span class="node-type-badge" id="nodeTypeBadge"></span>
            <div class="node-description" id="nodeDescription"></div>
        </div>
    `;
    
    // Create graph container
    var graphContainer = document.createElement('div');
    graphContainer.id = 'graphContainer';
    
    // Reparent mynetwork
    mynetwork.parentNode.insertBefore(mainContainer, mynetwork);
    mainContainer.appendChild(sidePanel);
    mainContainer.appendChild(graphContainer);
    graphContainer.appendChild(mynetwork);
    
    // Make mynetwork fill the graph container
    mynetwork.style.width = '100%';
    mynetwork.style.height = '100%';
}});
</script>
<script type="text/javascript">
(function() {{
    // Adjacency data
    var outEdges = {json.dumps(out_edges)};
    var inEdges = {json.dumps(in_edges)};
    var originalColors = {json.dumps(node_colors)};
    var nodeLabels = {json.dumps(node_labels)};
    var nodeDescriptions = {json.dumps(node_descriptions)};
    
    // Build node type lookup
    var nodeTypes = {json.dumps({nid: data.get("node_type", "unknown") for nid, data in G.nodes(data=True)})};
    
    // Wait for network to be ready
    function waitForNetwork() {{
        if (typeof network === 'undefined') {{
            setTimeout(waitForNetwork, 100);
            return;
        }}
        // Wait a bit more for DOM restructuring
        setTimeout(function() {{
            setupFocusMode();
            setupSearch();
            // Resize network to fit new container
            network.redraw();
            network.fit();
        }}, 200);
    }}
    
    function setupSearch() {{
        var searchInput = document.getElementById('searchInput');
        var searchResults = document.getElementById('searchResults');
        
        // Build searchable list
        var nodeList = [];
        for (var nodeId in nodeLabels) {{
            nodeList.push({{
                id: nodeId,
                label: nodeLabels[nodeId],
                type: nodeTypes[nodeId]
            }});
        }}
        
        searchInput.addEventListener('input', function() {{
            var query = this.value.toLowerCase().trim();
            if (query.length < 2) {{
                searchResults.classList.remove('active');
                searchResults.innerHTML = '';
                return;
            }}
            
            var matches = nodeList.filter(function(node) {{
                return node.label.toLowerCase().includes(query);
            }}).slice(0, 20);
            
            if (matches.length === 0) {{
                searchResults.innerHTML = '<div class="search-item">No matches found</div>';
            }} else {{
                searchResults.innerHTML = matches.map(function(node) {{
                    return '<div class="search-item" data-id="' + node.id + '">' +
                           '<div>' + node.label + '</div>' +
                           '<div class="node-type">' + node.type + '</div></div>';
                }}).join('');
            }}
            searchResults.classList.add('active');
        }});
        
        searchResults.addEventListener('click', function(e) {{
            var item = e.target.closest('.search-item');
            if (item && item.dataset.id) {{
                var nodeId = item.dataset.id;
                network.selectNodes([nodeId]);
                network.focus(nodeId, {{
                    scale: 1.5,
                    animation: {{
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }}
                }});
                
                // Trigger the focus behavior
                var hideCheckbox = document.getElementById('hideUnreachable');
                applyFocus(nodeId, hideCheckbox.checked);
                
                searchInput.value = '';
                searchResults.classList.remove('active');
                searchResults.innerHTML = '';
            }}
        }});
        
        // Close results when clicking outside
        document.addEventListener('click', function(e) {{
            if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {{
                searchResults.classList.remove('active');
            }}
        }});
    }}
    
    var applyFocus; // Will be set by setupFocusMode
    
    function setupFocusMode() {{
        var allNodes = network.body.data.nodes;
        var allEdges = network.body.data.edges;
        var hideCheckbox = document.getElementById('hideUnreachable');
        var statusDiv = document.getElementById('focusStatus');
        var nodeDetails = document.getElementById('nodeDetails');
        var nodeTitle = document.getElementById('nodeTitle');
        var nodeTypeBadge = document.getElementById('nodeTypeBadge');
        var nodeDescription = document.getElementById('nodeDescription');
        
        // Store original node data
        var originalNodeData = {{}};
        allNodes.forEach(function(node) {{
            originalNodeData[node.id] = {{
                color: node.color,
                label: node.label,
                font: node.font || {{}},
                hidden: false
            }};
        }});
        
        // Store original edge data
        var originalEdgeData = {{}};
        allEdges.forEach(function(edge) {{
            originalEdgeData[edge.id] = {{
                color: edge.color,
                hidden: false
            }};
        }});
        
        var currentFocusNode = null;
        
        function showNodeDetails(nodeId) {{
            var label = nodeLabels[nodeId] || nodeId;
            var type = nodeTypes[nodeId] || 'unknown';
            var desc = nodeDescriptions[nodeId] || '';
            
            nodeTitle.textContent = label;
            nodeTypeBadge.textContent = type;
            nodeTypeBadge.className = 'node-type-badge ' + type;
            nodeDescription.textContent = desc;
            nodeDetails.classList.add('active');
        }}
        
        function hideNodeDetails() {{
            nodeDetails.classList.remove('active');
        }}
        
        // Compute forward reachable nodes (following out-edges)
        function forwardReachable(startNode) {{
            var visited = new Set();
            var queue = [startNode];
            while (queue.length > 0) {{
                var node = queue.shift();
                if (visited.has(node)) continue;
                visited.add(node);
                var successors = outEdges[node] || [];
                for (var i = 0; i < successors.length; i++) {{
                    if (!visited.has(successors[i])) {{
                        queue.push(successors[i]);
                    }}
                }}
            }}
            return visited;
        }}
        
        // Compute backward reachable nodes (following in-edges)
        function backwardReachable(startNode) {{
            var visited = new Set();
            var queue = [startNode];
            while (queue.length > 0) {{
                var node = queue.shift();
                if (visited.has(node)) continue;
                visited.add(node);
                var predecessors = inEdges[node] || [];
                for (var i = 0; i < predecessors.length; i++) {{
                    if (!visited.has(predecessors[i])) {{
                        queue.push(predecessors[i]);
                    }}
                }}
            }}
            return visited;
        }}
        
        function resetGraph() {{
            currentFocusNode = null;
            statusDiv.textContent = 'Click a node to focus';
            statusDiv.classList.remove('active');
            hideNodeDetails();
            
            var updates = [];
            allNodes.forEach(function(node) {{
                var orig = originalNodeData[node.id];
                updates.push({{
                    id: node.id,
                    color: orig.color,
                    label: orig.label,
                    font: {{ color: '#000000' }},
                    hidden: false
                }});
            }});
            allNodes.update(updates);
            
            var edgeUpdates = [];
            allEdges.forEach(function(edge) {{
                edgeUpdates.push({{
                    id: edge.id,
                    color: originalEdgeData[edge.id].color,
                    hidden: false
                }});
            }});
            allEdges.update(edgeUpdates);
        }}
        
        applyFocus = function(selectedNode, hideMode) {{
            currentFocusNode = selectedNode;
            showNodeDetails(selectedNode);
            
            // Compute reachable nodes in both directions
            var forwardSet = forwardReachable(selectedNode);
            var backwardSet = backwardReachable(selectedNode);
            var reachableSet = new Set([...forwardSet, ...backwardSet]);
            
            var reachableCount = reachableSet.size;
            var totalCount = Object.keys(originalNodeData).length;
            statusDiv.textContent = 'Focused: ' + reachableCount + ' of ' + totalCount + ' nodes';
            statusDiv.classList.add('active');
            
            // Update node appearance
            var updates = [];
            allNodes.forEach(function(node) {{
                var orig = originalNodeData[node.id];
                if (node.id === selectedNode) {{
                    updates.push({{
                        id: node.id,
                        color: orig.color,
                        label: orig.label,
                        font: {{ color: '#000000', bold: true }},
                        hidden: false
                    }});
                }} else if (reachableSet.has(node.id)) {{
                    updates.push({{
                        id: node.id,
                        color: orig.color,
                        label: orig.label,
                        font: {{ color: '#000000' }},
                        hidden: false
                    }});
                }} else {{
                    if (hideMode) {{
                        updates.push({{
                            id: node.id,
                            hidden: true
                        }});
                    }} else {{
                        updates.push({{
                            id: node.id,
                            color: '#e0e0e0',
                            label: '',
                            font: {{ color: '#e0e0e0' }},
                            hidden: false
                        }});
                    }}
                }}
            }});
            allNodes.update(updates);
            
            // Update edge appearance
            var edgeUpdates = [];
            allEdges.forEach(function(edge) {{
                var fromReachable = reachableSet.has(edge.from);
                var toReachable = reachableSet.has(edge.to);
                if (fromReachable && toReachable) {{
                    edgeUpdates.push({{
                        id: edge.id,
                        color: originalEdgeData[edge.id].color,
                        hidden: false
                    }});
                }} else {{
                    if (hideMode) {{
                        edgeUpdates.push({{
                            id: edge.id,
                            hidden: true
                        }});
                    }} else {{
                        edgeUpdates.push({{
                            id: edge.id,
                            color: '#e0e0e0',
                            hidden: false
                        }});
                    }}
                }}
            }});
            allEdges.update(edgeUpdates);
            
            // If hiding nodes, fit view to visible nodes
            if (hideMode) {{
                network.fit({{
                    animation: {{
                        duration: 500,
                        easingFunction: 'easeInOutQuad'
                    }}
                }});
            }}
        }}
        
        // Handle checkbox change - reapply focus if there's a current focus
        hideCheckbox.addEventListener('change', function() {{
            if (currentFocusNode !== null) {{
                applyFocus(currentFocusNode, hideCheckbox.checked);
            }}
        }});
        
        // Handle node click
        network.on("click", function(params) {{
            if (params.nodes.length === 0) {{
                resetGraph();
                return;
            }}
            
            var selectedNode = params.nodes[0];
            
            // Shift+Click toggles hide mode
            if (params.event.srcEvent.shiftKey) {{
                hideCheckbox.checked = !hideCheckbox.checked;
            }}
            
            applyFocus(selectedNode, hideCheckbox.checked);
        }});
    }}
    
    waitForNetwork();
}})();
</script>
'''
    
    # Read the HTML file and inject the script before </body>
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    html_content = html_content.replace('</body>', js_code + '</body>')
    
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def create_visualization(
    output_path: str = "threat_model.html",
    height: str = "900px",
    width: str = "100%",
) -> None:
    """
    Create an interactive Pyvis visualization of the threat model.
    """
    # Build the model graph
    G = threat_model.graph
    
    # Create Pyvis network
    net = Network(
        height=height,
        width=width,
        directed=True,
        bgcolor="#ffffff",
        font_color=False,
        select_menu=False,
        filter_menu=False,
    )
    
    # Configure physics for better layout
    net.barnes_hut(
        gravity=-3000,
        central_gravity=0.3,
        spring_length=150,
        spring_strength=0.05,
        damping=0.09,
    )
    
    # Add nodes
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_obj = data.get("node")
        
        # Build label and title (hover text)
        if node_type == "property":
            label = node_obj.id
            desc = node_obj.description[:200] + "..." if len(node_obj.description) > 200 else node_obj.description
            title = f"<b>{node_obj.id}</b><br><br>{desc}"
        elif node_type == "attack":
            label = node_obj.name[:30] + "..." if len(node_obj.name) > 30 else node_obj.name
            contexts = ", ".join(c.id for c in node_obj.occurs_in) if node_obj.occurs_in else "N/A"
            title = f"<b>{node_obj.name}</b><br><br>ID: {node_obj.id}<br>Contexts: {contexts}"
            if node_obj.description:
                title += f"<br><br>{node_obj.description[:300]}..."
        elif node_type == "pattern":
            label = node_obj.name[:30] + "..." if len(node_obj.name) > 30 else node_obj.name
            title = f"<b>Pattern: {node_obj.name}</b><br><br>ID: {node_obj.id}"
            if node_obj.description:
                title += f"<br><br>{node_obj.description[:300]}..."
        elif node_type == "mitigation":
            label = node_obj.name[:25] + "..." if len(node_obj.name) > 25 else node_obj.name
            title = f"<b>Mitigation: {node_obj.name}</b><br><br>ID: {node_obj.id}"
            if node_obj.description:
                title += f"<br><br>{node_obj.description[:300]}..."
        elif node_type == "context":
            label = node_obj.id
            title = f"<b>Context: {node_obj.id}</b><br><br>{node_obj.name}"
        else:
            label = str(node_id)
            title = str(node_id)
        
        net.add_node(
            node_id,
            label=label,
            title=title,
            color=NODE_COLORS.get(node_type, "#888888"),
            shape=NODE_SHAPES.get(node_type, "dot"),
            size=25 if node_type in ("property", "attack") else 20,
            group=node_type,
        )
    
    # Add edges
    for source, target, data in G.edges(data=True):
        edge_type = data.get("edge_type", EdgeType.REFINES)
        
        # Build edge title (hover text)
        title = edge_type.value
        if "rationale" in data and data["rationale"]:
            title += f"<br><br>{data['rationale'][:200]}..."
        
        net.add_edge(
            source,
            target,
            title=title,
            color=EDGE_COLORS.get(edge_type, "#888888"),
            arrows="to",
            smooth={"type": "curvedCW", "roundness": 0.1},
        )
    
    # Generate HTML
    net.write_html(output_path)
    
    # Add custom JavaScript for directional transitive reachability
    _inject_focus_mode_js(output_path, G)
    
    print(f"Visualization saved to: {output_path}")
    print(f"  Nodes: {G.number_of_nodes()}")
    print(f"  Open in a browser to explore the threat model interactively.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate interactive threat model visualizations"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="threat_model.html",
        help="Output HTML file path",
    )
    
    args = parser.parse_args()
    create_visualization(output_path=args.output)


if __name__ == "__main__":
    main()
