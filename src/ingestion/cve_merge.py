"""Merges Kaggle CVE data + CISA KEV + EPSS snapshot into microsoft_cve_master.csv."""
import ast
import glob
import pathlib

import pandas as pd

MICROSOFT_ALIASES = [
    "microsoft", "windows", "azure", "office", "exchange", "sql server",
    ".net", "edge", "sharepoint", "active directory",
]

RAW_DIR = pathlib.Path("data/raw")
OUT_PATH = pathlib.Path("data/processed/microsoft_cve_master.csv")


def parse_list_field(raw) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        parsed = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def cpe_vendor_product(cpe_uri: str) -> tuple[str, str]:
    parts = cpe_uri.split(":")
    vendor = parts[3].replace("_", " ") if len(parts) > 3 else ""
    product = parts[4].replace("_", " ") if len(parts) > 4 else ""
    return vendor, product


def is_microsoft_scope(fields: list[str]) -> bool:
    haystack = " ".join(f.lower() for f in fields if f)
    return any(alias in haystack for alias in MICROSOFT_ALIASES)


def load_epss_snapshot(epss_glob: str) -> pd.DataFrame:
    import gzip
    matches = sorted(glob.glob(epss_glob))
    if not matches:
        raise FileNotFoundError(f"No EPSS snapshot matching {epss_glob}")
    filepath = matches[-1]
    try:
        df = pd.read_csv(filepath, comment="#")
    except gzip.BadGzipFile:
        # Handle uncompressed files with .gz extension (e.g., in tests)
        df = pd.read_csv(filepath, compression=None, comment="#")
    return df.rename(columns={"cve": "cve_id", "epss": "epss_score", "percentile": "epss_percentile"})


def build_microsoft_cve_master(kaggle_dir: pathlib.Path, kev_path: pathlib.Path, epss_glob: str) -> pd.DataFrame:
    enriched = pd.read_csv(kaggle_dir / "cve_cisa_epss_enriched_dataset.csv")
    corpus = pd.read_csv(kaggle_dir / "cve_corpus.csv")
    merged = enriched.merge(corpus, on="cve_id", how="inner")

    merged["description"] = merged["description_data"].apply(
        lambda v: (parse_list_field(v) or [""])[0]
    )
    merged["cwe_id_from_corpus"] = merged["cwe_data"].apply(
        lambda v: next((c for c in parse_list_field(v) if c.startswith("CWE-")), None)
    )
    cpe_vp = merged["cpe_data"].apply(
        lambda v: cpe_vendor_product(parse_list_field(v)[0]) if parse_list_field(v) else ("", "")
    )
    merged["cpe_vendor"] = cpe_vp.apply(lambda t: t[0])
    merged["cpe_product"] = cpe_vp.apply(lambda t: t[1])

    kev = pd.read_csv(kev_path).rename(columns={"cveID": "cve_id"})
    kev_cols = ["cve_id", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse", "cwes"]
    merged = merged.merge(kev[kev_cols], on="cve_id", how="left")

    merged["kev_flag"] = merged["vendorProject"].notna()
    merged["vendor"] = merged["vendorProject"].fillna(merged["cpe_vendor"])
    merged["product"] = merged["product"].fillna(merged["cpe_product"])

    # Merge EPSS before scope filter (per requirements)
    epss = load_epss_snapshot(epss_glob)
    merged = merged.merge(epss, on="cve_id", how="left", suffixes=("_old", ""))
    merged["epss_score"] = merged["epss_score"].fillna(merged["epss_score_old"])
    merged["epss_percentile"] = merged["epss_percentile"].fillna(merged["epss_perc"])

    # CWE fallback: use KEV cwes if corpus cwe_data is empty
    def extract_cwe_fallback(row):
        if row["cwe_id_from_corpus"]:
            return row["cwe_id_from_corpus"]
        if pd.notna(row["cwes"]):
            cwes_raw = str(row["cwes"]).strip()
            # Try parsing as list string first (e.g., "['CWE-269', 'CWE-287']")
            parsed = parse_list_field(cwes_raw)
            if parsed:
                return next((c for c in parsed if c.startswith("CWE-")), None)
            # Handle comma-separated format (e.g., "CWE-269, CWE-287, CWE-306")
            if "," in cwes_raw:
                for token in cwes_raw.split(","):
                    token = token.strip()
                    if token.startswith("CWE-"):
                        return token
            # Handle single CWE code (e.g., "CWE-269")
            if cwes_raw.startswith("CWE-"):
                return cwes_raw
        return None

    merged["cwe_id"] = merged.apply(extract_cwe_fallback, axis=1)

    # Apply scope filter based only on vendor/product (not description)
    scope_mask = merged.apply(
        lambda r: r["kev_flag"] or is_microsoft_scope([r["vendor"], r["product"]]),
        axis=1,
    )
    merged = merged[scope_mask].copy()

    merged = merged.rename(columns={
        "dateAdded": "kev_date_added",
        "knownRansomwareCampaignUse": "ransomware_used",
    })

    result = merged[[
        "cve_id", "vendor", "product", "description", "cwe_id", "base_severity",
        "base_score", "attack_vector", "epss_score", "epss_percentile", "kev_flag",
        "kev_date_added", "ransomware_used", "published_date",
    ]].drop_duplicates(subset="cve_id").reset_index(drop=True)
    return result


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df = build_microsoft_cve_master(
        RAW_DIR / "kaggle merged dataset",
        RAW_DIR / "kev_catalog.csv",
        str(RAW_DIR / "epss_scores-*.csv.gz"),
    )
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} rows to {OUT_PATH}")


if __name__ == "__main__":
    main()
