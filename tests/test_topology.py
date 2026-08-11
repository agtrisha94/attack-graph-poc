from src.generator.topology import generate_topology, MANAGEMENT_GROUPS

VALID_NODE_TYPES = {"User", "Group", "Computer", "Application", "Device"}
VALID_EDGE_TYPES = {"RUNS", "CONNECTS_TO", "MEMBER_OF", "HAS_SESSION", "CONTROLS"}
VALID_CRITICALITY = {"Crown Jewel", "High", "Medium", "Low"}


def test_generate_topology_is_deterministic():
    nodes_a, edges_a = generate_topology(["Exchange Server", "SQL Server"], seed=42)
    nodes_b, edges_b = generate_topology(["Exchange Server", "SQL Server"], seed=42)
    assert nodes_a.equals(nodes_b)
    assert edges_a.equals(edges_b)


def test_generate_topology_produces_valid_nodes_and_edges():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)

    assert len(nodes) > 0
    assert set(nodes["node_type"]).issubset(VALID_NODE_TYPES)
    assert set(nodes["criticality_tier"]).issubset(VALID_CRITICALITY)
    assert set(nodes["management_group"]).issubset(set(MANAGEMENT_GROUPS))
    assert nodes["node_id"].is_unique

    assert len(edges) > 0
    assert set(edges["edge_type"]).issubset(VALID_EDGE_TYPES)
    node_ids = set(nodes["node_id"])
    assert set(edges["source_id"]).issubset(node_ids)
    assert set(edges["target_id"]).issubset(node_ids)
