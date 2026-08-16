from collections import deque

from src.generator.topology import (
    ADMINS_PER_MG,
    COMPUTERS_PER_MG,
    MANAGEMENT_GROUPS,
    USERS_PER_MG,
    generate_topology,
)

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


def test_generate_topology_node_count_matches_per_mg_formula():
    products = ["Exchange Server", "SQL Server"]
    apps_per_computer = min(2, len(products))
    nodes, _ = generate_topology(products, seed=1)

    expected = len(MANAGEMENT_GROUPS) * (
        1 + COMPUTERS_PER_MG + COMPUTERS_PER_MG * apps_per_computer + USERS_PER_MG
    )
    assert len(nodes) == expected


def test_generate_topology_criticality_varies_within_a_group():
    nodes, _ = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    identity_tiers = set(nodes[nodes["management_group"] == "Platform/Identity"]["criticality_tier"])
    assert len(identity_tiers) > 1


def test_generate_topology_has_internet_facing_entry_points():
    nodes, _ = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    assert nodes["internet_facing"].sum() > 0


def test_generate_topology_has_no_isolated_computers():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    non_run_touched = set(edges[edges["edge_type"] != "RUNS"]["source_id"]) | set(
        edges[edges["edge_type"] != "RUNS"]["target_id"]
    )
    computer_ids = set(nodes[nodes["node_type"] == "Computer"]["node_id"])
    assert computer_ids.issubset(non_run_touched)


def test_generate_topology_workstations_can_reach_a_server():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    workstation_ids = set(nodes[nodes["role"] == "workstation"]["node_id"])
    server_ids = set(nodes[nodes["role"].isin(["server", "domain_controller"])]["node_id"])
    reachable = set(
        edges[(edges["edge_type"] == "CONNECTS_TO") & (edges["source_id"].isin(workstation_ids)) & (edges["target_id"].isin(server_ids))]["source_id"]
    )
    assert workstation_ids.issubset(reachable)


def test_generate_topology_identity_has_a_single_external_gateway():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    identity_ids = set(nodes[nodes["management_group"] == "Platform/Identity"]["node_id"])
    inbound = edges[(edges["edge_type"] == "CONNECTS_TO") & (edges["target_id"].isin(identity_ids))]
    external_sources = set(inbound["source_id"]) - identity_ids
    assert len(external_sources) == 1


def test_generate_topology_is_admin_flag_matches_controls_edges():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    flagged_admins = set(nodes[(nodes["node_type"] == "User") & (nodes["is_admin"])]["node_id"])

    for mg in MANAGEMENT_GROUPS:
        mg_user_ids = set(nodes[(nodes["management_group"] == mg) & (nodes["node_type"] == "User")]["node_id"])
        assert len(flagged_admins & mg_user_ids) == ADMINS_PER_MG

    controlling_users = set(
        edges[(edges["edge_type"] == "CONTROLS") & (edges["source_id"].isin(nodes[nodes["node_type"] == "User"]["node_id"]))][
            "source_id"
        ]
    )
    assert flagged_admins == controlling_users


def test_generate_topology_is_a_single_connected_component():
    # Regression: the group's CONTROLS edge used to target a *random*
    # server. Whenever that random pick (and both admin users' picks)
    # missed the gateway, nothing else in the group ever linked to it --
    # the gateway stayed reachable from outside the group (via the
    # cross-group mesh) but the rest of the group (users, workstations,
    # local servers) became a separate component, unreachable from
    # anywhere else in the graph despite every individual node having
    # *some* edge. Checked across several seeds since it's luck-of-the-draw
    # whether a given seed happens to trigger it.
    for seed in (1, 2, 3, 42):
        nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=seed)
        adjacency: dict[str, set[str]] = {}
        for _, row in edges.iterrows():
            adjacency.setdefault(row["source_id"], set()).add(row["target_id"])
            adjacency.setdefault(row["target_id"], set()).add(row["source_id"])

        all_ids = set(nodes["node_id"])
        start = next(iter(all_ids))
        visited = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, ()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        assert visited == all_ids, f"seed={seed}: {len(all_ids) - len(visited)} node(s) unreachable"


def test_generate_topology_workstations_cannot_reach_gateway_directly():
    nodes, edges = generate_topology(["Exchange Server", "SQL Server"], seed=1)
    workstation_ids = set(nodes[nodes["role"] == "workstation"]["node_id"])
    for mg in MANAGEMENT_GROUPS:
        mg_servers = nodes[
            (nodes["management_group"] == mg) & (nodes["role"].isin(["server", "domain_controller"]))
        ].sort_values("node_id")
        gateway_id = mg_servers.iloc[0]["node_id"]
        touching_gateway = set(
            edges[(edges["edge_type"] == "CONNECTS_TO") & (edges["target_id"] == gateway_id)]["source_id"]
        )
        assert touching_gateway.isdisjoint(workstation_ids)
