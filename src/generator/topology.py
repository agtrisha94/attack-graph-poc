"""Generates a synthetic enterprise topology shaped after AzureHound's object
model, grounded in the Enterprise-Scale management group hierarchy documented
in data/raw/azure-enterprise-scale/docs/reference/contoso/Readme.md, with
node roles and connectivity following the Microsoft Active Directory tiering
model (Tier 0 domain controllers / Tier 1 servers / Tier 2 workstations).

Each group's first server is its "gateway" -- the only node used for
cross-group connectivity and the internet-facing entry point where
applicable. Ordinary workstations can reach the group's other ("local")
servers over the LAN, but not the gateway -- only an admin CONTROLS edge
crosses that boundary. This is what keeps blast radius (and thus which
node shows up as a choke point) meaningfully tied to network segmentation
instead of every asset being a few hops from everything else.
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

# Tier for the group's own admin node. Computer/User tiers are assigned
# per-role below (ROLE_TIER / DOMAIN_CONTROLLER_TIER / USER_TIER), not by
# blanket group membership.
GROUP_TIER = {
    "Platform/Identity": "Crown Jewel",
    "Platform/Management": "High",
    "Platform/Connectivity": "High",
    "LandingZones/Corp": "Medium",
    "LandingZones/Online": "Medium",
}

ROLE_LABEL = {"domain_controller": "DomainController", "server": "Server", "workstation": "Workstation"}
ROLE_TIER = {"server": "High", "workstation": "Medium"}
DOMAIN_CONTROLLER_TIER = "Crown Jewel"
USER_TIER = "Low"

COMPUTERS_PER_MG = 20
SERVERS_PER_MG = 3
USERS_PER_MG = 15
ADMINS_PER_MG = 2

# Keyword match used to bias installed_software on internet-facing hosts
# toward the classic real-world internet-exposed Microsoft attack surface
# (Exchange/SharePoint/IIS/Outlook), instead of a purely cosmetic flag.
INTERNET_FACING_PRODUCT_KEYWORDS = ("exchange", "sharepoint", "iis", "outlook")

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

    exposed_products = [p for p in products if any(k in p.lower() for k in INTERNET_FACING_PRODUCT_KEYWORDS)]

    def pick_software(internet_facing: bool) -> list[str]:
        k = min(2, len(products))
        if k == 0:
            return []
        if internet_facing and exposed_products:
            chosen = rng.sample(exposed_products, k=min(k, len(exposed_products)))
            remaining = [p for p in products if p not in chosen]
            if len(chosen) < k and remaining:
                chosen += rng.sample(remaining, k=min(k - len(chosen), len(remaining)))
            return chosen
        return rng.sample(products, k=k)

    server_ids_by_mg: dict[str, list[str]] = {}
    user_ids_by_mg: dict[str, list[str]] = {}

    for mg in MANAGEMENT_GROUPS:
        group_id = next_id("group")
        nodes.append({
            "node_id": group_id, "node_type": "Group",
            "display_name": f"{mg.split('/')[-1]}-Admins",
            "criticality_tier": GROUP_TIER[mg], "installed_software": "",
            "management_group": mg, "role": "", "internet_facing": False, "is_admin": False,
        })

        # The two plausible attacker entry points: Connectivity's gateway
        # server (VPN/firewall, index 0 -- see the gateway/local split below)
        # and Online's first local server (public web app, index 1).
        gateway_index = 0 if mg == "Platform/Connectivity" else None
        webapp_index = 1 if mg == "LandingZones/Online" else None

        servers: list[str] = []
        workstations: list[str] = []
        for i in range(COMPUTERS_PER_MG):
            is_server = i < SERVERS_PER_MG
            if mg == "Platform/Identity" and is_server:
                role, tier = "domain_controller", DOMAIN_CONTROLLER_TIER
            elif is_server:
                role, tier = "server", ROLE_TIER["server"]
            else:
                role, tier = "workstation", ROLE_TIER["workstation"]
            is_internet_facing = is_server and i in (gateway_index, webapp_index)

            cid = next_id("computer")
            software = pick_software(is_internet_facing)
            nodes.append({
                "node_id": cid, "node_type": "Computer",
                "display_name": f"{mg.split('/')[-1]}-{ROLE_LABEL[role]}-{cid}",
                "criticality_tier": tier,
                "installed_software": ";".join(software),
                "management_group": mg, "role": role,
                "internet_facing": is_internet_facing, "is_admin": False,
            })
            (servers if is_server else workstations).append(cid)
            for app in software:
                app_id = next_id("app")
                nodes.append({
                    "node_id": app_id, "node_type": "Application",
                    "display_name": app, "criticality_tier": tier,
                    "installed_software": "", "management_group": mg,
                    "role": "", "internet_facing": False, "is_admin": False,
                })
                edges.append({"source_id": cid, "target_id": app_id, "edge_type": "RUNS", "properties": ""})

        server_ids_by_mg[mg] = servers
        # Segmentation: only the first server (the "gateway" -- also the
        # inter-group mesh endpoint below) is withheld from ordinary
        # workstation LAN access. Regular workstations can reach the
        # group's other ("local") servers directly -- a file share, that
        # kind of thing -- but reaching the gateway itself, and therefore
        # crossing into another management group, requires an admin
        # CONTROLS edge, not just being on the LAN. Without this split,
        # every workstation was one hop from the same node used for
        # cross-group routing, so blast radius from almost any starting
        # point covered nearly the whole 380-asset inventory -- no
        # meaningful segmentation despite the tiering.
        local_servers = servers[1:]

        # Plain LAN reachability to a local server (e.g. a file share),
        # independent of who's logged in or who has admin rights on it --
        # without this, a compromised workstation is a dead end unless its
        # one user happens to be one of the group's admins. This is also
        # what breaks the group from being a pure two-level tree (which
        # force-directed layout always draws as a bullseye) into a graph
        # with real cycles.
        for workstation in workstations:
            edges.append({
                "source_id": workstation, "target_id": rng.choice(local_servers),
                "edge_type": "CONNECTS_TO", "properties": "",
            })

        user_ids: list[str] = []
        user_node_by_id: dict[str, dict] = {}
        session_covered: set[str] = set()
        for _ in range(USERS_PER_MG):
            uid = next_id("user")
            user_node = {
                "node_id": uid, "node_type": "User",
                "display_name": f"{mg.split('/')[-1]}-User-{uid}",
                "criticality_tier": USER_TIER, "installed_software": "",
                "management_group": mg, "role": "", "internet_facing": False,
                "is_admin": False,
            }
            nodes.append(user_node)
            user_node_by_id[uid] = user_node
            user_ids.append(uid)
            edges.append({"source_id": uid, "target_id": group_id, "edge_type": "MEMBER_OF", "properties": ""})
            workstation = rng.choice(workstations)
            session_covered.add(workstation)
            edges.append({"source_id": uid, "target_id": workstation, "edge_type": "HAS_SESSION", "properties": ""})
        # A handful of workstations inevitably get missed by random draws
        # (more workstations than users per group) -- every inventoried
        # workstation should have someone logging into it, so top up the
        # ones nobody was randomly assigned to instead of leaving them as
        # disconnected islands.
        for workstation in workstations:
            if workstation not in session_covered:
                edges.append({
                    "source_id": rng.choice(user_ids), "target_id": workstation,
                    "edge_type": "HAS_SESSION", "properties": "",
                })

        user_ids_by_mg[mg] = user_ids

        # The admin group controls the gateway specifically (not a random
        # server) -- domain admins managing the perimeter/firewall box is
        # realistic, and it's also the only guaranteed edge tying the
        # gateway back into the rest of its own group's structure. Random
        # choice here previously meant that whenever neither this edge nor
        # either admin user's pick (below) happened to land on the gateway,
        # the entire rest of the group (users, workstations, local servers)
        # ended up in a completely separate connected component from the
        # gateway -- reachable from outside the group but not from inside
        # it -- since nothing else in the group ever links to the gateway.
        # A small admin subset of users additionally get direct control
        # over a (random) server -- real AD admin rights are held by
        # accounts, not just inferred from group membership.
        edges.append({
            "source_id": group_id, "target_id": servers[0],
            "edge_type": "CONTROLS", "properties": "",
        })
        for admin_id in rng.sample(user_ids, k=min(ADMINS_PER_MG, len(user_ids))):
            user_node_by_id[admin_id]["is_admin"] = True
            edges.append({
                "source_id": admin_id, "target_id": rng.choice(servers),
                "edge_type": "CONTROLS", "properties": "",
            })

    # Enterprise-Scale VWAN model, one narrow link per hop instead of a
    # redundant mesh: each landing zone/mgmt group's gateway server links to
    # Connectivity's gateway, which links to Identity's gateway domain
    # controller. A single link per boundary is what makes it a real choke
    # point -- redundant parallel links don't shorten the attacker's path
    # (blast radius doesn't care how many equally-short routes exist), they
    # just dilute which node shows up as "the" choke point.
    connectivity_servers = server_ids_by_mg["Platform/Connectivity"]
    identity_gateway = server_ids_by_mg["Platform/Identity"][0]
    connectivity_gateway = connectivity_servers[0]
    edges.append({
        "source_id": connectivity_gateway, "target_id": identity_gateway,
        "edge_type": "CONNECTS_TO", "properties": "",
    })
    for mg in ["Platform/Management", "LandingZones/Corp", "LandingZones/Online"]:
        local_gateway = server_ids_by_mg[mg][0]
        edges.append({
            "source_id": local_gateway, "target_id": connectivity_gateway,
            "edge_type": "CONNECTS_TO", "properties": "",
        })

    # The internet-facing VPN gateway also links into one of Connectivity's
    # own local servers -- models "breach the gateway, pivot inward."
    edges.append({
        "source_id": connectivity_gateway, "target_id": connectivity_servers[1],
        "edge_type": "CONNECTS_TO", "properties": "",
    })

    # Servers only get a CONTROLS/CONNECTS_TO edge if they were the lucky
    # random pick for admin control, a local server some workstation
    # happened to connect to, or the one server wired into the inter-group
    # mesh -- that can still leave a local server with no non-RUNS edge at
    # all (an isolated computer+app island). Same repair as the workstation
    # top-up above, applied once the mesh links are final.
    linked = {e["source_id"] for e in edges if e["edge_type"] != "RUNS"} | {
        e["target_id"] for e in edges if e["edge_type"] != "RUNS"
    }
    for n in nodes:
        if n["node_type"] == "Computer" and n["role"] != "workstation" and n["node_id"] not in linked:
            edges.append({
                "source_id": rng.choice(user_ids_by_mg[n["management_group"]]),
                "target_id": n["node_id"], "edge_type": "CONTROLS", "properties": "",
            })

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
