import pandas as pd
from src.ingestion.cve_merge import (
    parse_list_field,
    cpe_vendor_product,
    is_microsoft_scope,
    build_microsoft_cve_master,
)


def test_parse_list_field_parses_python_list_string():
    assert parse_list_field("['CWE-79']") == ["CWE-79"]


def test_parse_list_field_handles_missing():
    assert parse_list_field(float("nan")) == []
    assert parse_list_field("") == []


def test_cpe_vendor_product_extracts_vendor_and_product():
    assert cpe_vendor_product("cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*") == (
        "microsoft",
        "sql server",
    )


def test_is_microsoft_scope_matches_alias_substring():
    assert is_microsoft_scope(["microsoft", "sql server"]) is True
    assert is_microsoft_scope(["windows_10"]) is True
    assert is_microsoft_scope(["eric_allman", "sendmail"]) is False


def test_build_microsoft_cve_master_filters_and_merges(tmp_path):
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0001,HIGH,8.8,0.1,0.5,False,NETWORK,2026-01-01\n"
        "CVE-2026-0002,LOW,2.0,0.01,0.1,False,LOCAL,2026-01-02\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0001,["RCE in Exchange"],["CWE-502"],'
        '["cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"]\n'
        'CVE-2026-0002,["local bug in sendmail"],["CWE-20"],'
        '["cpe:2.3:a:eric_allman:sendmail:8.15:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse\n"
        "CVE-2026-0001,Microsoft,Exchange Server,2026-01-05,Known\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [
                {"cve": "CVE-2026-0001", "epss": 0.42, "percentile": 0.9},
                {"cve": "CVE-2026-0002", "epss": 0.02, "percentile": 0.2},
            ]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    assert list(result["cve_id"]) == ["CVE-2026-0001"]
    row = result.iloc[0]
    assert row["vendor"] == "Microsoft"
    assert row["kev_flag"] is True or row["kev_flag"] == True  # noqa: E712
    assert row["epss_score"] == 0.42
    assert row["epss_percentile"] == 0.9
    assert row["cwe_id"] == "CWE-502"
