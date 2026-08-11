"""Generates a synthetic enterprise topology shaped after AzureHound's object
model, grounded in the Enterprise-Scale management group hierarchy documented
in data/raw/azure-enterprise-scale/docs/reference/contoso/Readme.md.
"""
import pathlib
import random

import pandas as pd

MANAGEMENT_GROUPS = [
    "Platform/Management",
    "Platform/Connectivity",
    "Platform/Identity",
    "LandingZones/Corp",
    "LandingZones/Online",
]

CRITICALITY_BY_MG = {
    "Platform/Identity": "Crown Jewel",
    "Platform/Management": "High",
    "Platform/Connectivity": "High",
    "LandingZones/Corp": "Medium",
    "LandingZones/Online": "Medium",
}

COMPUTERS_PER_MG = 4
USERS_PER_MG = 3

CVE_MASTER_PATH = pathlib.Path("data/processed/microsoft_cve_master.csv")
NODES_OUT = pathlib.Path("data/synthetic/nodes_topology.csv")
EDGES_OUT = pathlib.Path("data/synthetic/edges_topology.csv")


def generate_topology(products: list[str], seed: int = 42) -> tuple[pd.DataFrame, pd.DataFrame]:
    rng = random.Random(seed)
    nodes: list[dict] = []
    edges: list[dict] = []
    counter = 0

    def next_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter:04d}"

    for mg in MANAGEMENT_GROUPS:
        tier = CRITICALITY_BY_MG[mg]

        group_id = next_id("group")
        nodes.append({
            "node_id": group_id, "node_type": "Group",
            "display_name": f"{mg.split('/')[-1]}-Admins",
            "criticality_tier": tier, "installed_software": "",
            "management_group": mg,
        })

        computer_ids = []
        for _ in range(COMPUTERS_PER_MG):
            cid = next_id("computer")
            software = rng.sample(products, k=min(2, len(products))) if products else []
            nodes.append({
                "node_id": cid, "node_type": "Computer",
                "display_name": f"{mg.split('/')[-1]}-Host-{cid}",
                "criticality_tier": tier,
                "installed_software": ";".join(software),
                "management_group": mg,
            })
            computer_ids.append(cid)
            for app in software:
                app_id = next_id("app")
                nodes.append({
                    "node_id": app_id, "node_type": "Application",
                    "display_name": app, "criticality_tier": tier,
                    "installed_software": "", "management_group": mg,
                })
                edges.append({"source_id": cid, "target_id": app_id, "edge_type": "RUNS", "properties": ""})

        for _ in range(USERS_PER_MG):
            uid = next_id("user")
            nodes.append({
                "node_id": uid, "node_type": "User",
                "display_name": f"{mg.split('/')[-1]}-User-{uid}",
                "criticality_tier": tier, "installed_software": "",
                "management_group": mg,
            })
            edges.append({"source_id": uid, "target_id": group_id, "edge_type": "MEMBER_OF", "properties": ""})
            edges.append({
                "source_id": uid, "target_id": rng.choice(computer_ids),
                "edge_type": "HAS_SESSION", "properties": "",
            })

        edges.append({
            "source_id": group_id, "target_id": rng.choice(computer_ids),
            "edge_type": "CONTROLS", "properties": "",
        })

    # Hub-and-spoke connectivity per the Enterprise-Scale VWAN model: every
    # landing zone connects through Connectivity, which connects through Identity.
    connectivity_computer = next(n["node_id"] for n in nodes if n["management_group"] == "Platform/Connectivity" and n["node_type"] == "Computer")
    identity_computer = next(n["node_id"] for n in nodes if n["management_group"] == "Platform/Identity" and n["node_type"] == "Computer")
    edges.append({"source_id": connectivity_computer, "target_id": identity_computer, "edge_type": "CONNECTS_TO", "properties": ""})
    for mg in ["LandingZones/Corp", "LandingZones/Online", "Platform/Management"]:
        first_computer = next(n["node_id"] for n in nodes if n["management_group"] == mg and n["node_type"] == "Computer")
        edges.append({"source_id": first_computer, "target_id": connectivity_computer, "edge_type": "CONNECTS_TO", "properties": ""})

    return pd.DataFrame(nodes), pd.DataFrame(edges)


def main() -> None:
    NODES_OUT.parent.mkdir(parents=True, exist_ok=True)
    products = pd.read_csv(CVE_MASTER_PATH)["product"].dropna().unique().tolist()
    nodes_df, edges_df = generate_topology(products)
    nodes_df.to_csv(NODES_OUT, index=False)
    edges_df.to_csv(EDGES_OUT, index=False)
    print(f"Wrote {len(nodes_df)} nodes to {NODES_OUT}, {len(edges_df)} edges to {EDGES_OUT}")


if __name__ == "__main__":
    main()
