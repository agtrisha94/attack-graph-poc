"""Shared streamlit-agraph rendering helper, reused by the Graph Explorer,
Attack Paths (path-chain), and Risk Analysis (blast-radius mini-graph)
pages -- avoids duplicating Node/Edge/Config construction three times.
Only node clicks round-trip to Python (streamlit-agraph's frontend wires a
selectNode event but no edge-click event), so edge inspection on every page
that needs it uses a table alongside the graph instead of a click handler."""
from streamlit_agraph import Config, Edge, Node, agraph


def render_graph(
    nodes: list[dict], edges: list[dict], height: int = 600, width: int = 1300,
    physics: bool = True,
) -> str | None:
    agraph_nodes = []
    for n in nodes:
        # x/y/fixed are optional -- only forwarded when a caller supplies an
        # explicit layout (e.g. Risk Analysis's radial blast-radius rings);
        # omitted entirely otherwise so physics-driven pages are unaffected.
        position_kwargs = {k: n[k] for k in ("x", "y", "fixed") if k in n}
        agraph_nodes.append(Node(
            id=n["id"],
            label=n.get("label", n["id"]),
            color=n.get("color"),
            size=n.get("size", 25),
            title=n.get("title"),
            **position_kwargs,
        ))
    agraph_edges = [
        Edge(source=e["source"], target=e["target"], label=e.get("label"))
        for e in edges
    ]
    # streamlit-agraph's Config formats height/width as f"{value}px" internally,
    # so these must be plain pixel ints, not CSS values like "100%".
    config = Config(height=height, width=width, directed=True, physics=physics, solver="forceAtlas2Based")
    # Config.__init__ only nests kwargs it explicitly knows about (like
    # "solver") into self.physics; unrecognized kwargs land as top-level
    # sibling keys instead, which vis.js's Network constructor ignores. Tuning
    # params for forceAtlas2Based must be nested under physics by hand.
    # forceAtlas2Based (vs vis.js's default barnesHut) pulls hub clusters
    # tighter instead of spreading same-hop-distance nodes into a uniform
    # ring around each hub -- barnesHut is what made every management
    # group's hub-and-spoke star render as a bullseye.
    config.physics["forceAtlas2Based"] = {
        "gravitationalConstant": -50, "springLength": 100,
        "springConstant": 0.08, "avoidOverlap": 0.5,
    }
    return agraph(nodes=agraph_nodes, edges=agraph_edges, config=config)
