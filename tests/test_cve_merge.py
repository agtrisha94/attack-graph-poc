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
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
        "CVE-2026-0001,Microsoft,Exchange Server,2026-01-05,Known,CWE-502\n"
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
    assert row["vendor"] == "microsoft"  # vendor is normalized to lowercase
    assert row["kev_flag"] is True or row["kev_flag"] == True  # noqa: E712
    assert row["epss_score"] == 0.42
    assert row["epss_percentile"] == 0.9
    assert row["cwe_id"] == "CWE-502"


def test_scope_filter_excludes_description_false_positives(tmp_path):
    """Verify scope filter doesn't match common English words in descriptions."""
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0099,LOW,3.0,0.01,0.1,False,LOCAL,2026-01-01\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0099,["vulnerability in edge computing device"],'
        '["CWE-79"],["cpe:2.3:a:acme_corp:sensor_firmware:1.0:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [{"cve": "CVE-2026-0099", "epss": 0.01, "percentile": 0.05}]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    # Description contains "edge" (a Microsoft alias word) but vendor/product don't match Microsoft scope
    assert len(result) == 0, "Non-Microsoft CVE should be excluded despite description containing 'edge'"


def test_cwe_fallback_to_kev_when_corpus_empty(tmp_path):
    """Verify CWE falls back to KEV catalog when not in corpus."""
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0003,HIGH,8.0,0.15,0.6,False,NETWORK,2026-01-01\n"
        "CVE-2026-0004,HIGH,8.5,0.2,0.7,False,NETWORK,2026-01-01\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0003,["Elevation of privilege in Windows kernel"],[],'
        '["cpe:2.3:o:microsoft:windows_10:21h2:*:*:*:*:*:*:*"]\n'
        'CVE-2026-0004,["Privilege escalation in Active Directory"],[],'
        '["cpe:2.3:a:microsoft:active_directory:2019:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
        "CVE-2026-0003,Microsoft,Windows 10,2026-01-05,Known,CWE-269\n"
        "CVE-2026-0004,Microsoft,Active Directory,2026-01-05,Known,\"CWE-269, CWE-287, CWE-306\"\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [
                {"cve": "CVE-2026-0003", "epss": 0.5, "percentile": 0.85},
                {"cve": "CVE-2026-0004", "epss": 0.55, "percentile": 0.9},
            ]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    assert len(result) == 2
    # Single CWE value fallback
    assert result.iloc[0]["cwe_id"] == "CWE-269", "Should fall back to KEV cwes when corpus cwe_data is empty"
    # Multi-CWE comma-separated fallback - should return first CWE
    assert result.iloc[1]["cwe_id"] == "CWE-269", "Should extract first CWE from comma-separated list"


def test_scope_filter_excludes_non_microsoft_kev_vendors(tmp_path):
    """Verify non-Microsoft vendors in KEV catalog are excluded (scope filter regression test)."""
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0005,HIGH,8.0,0.2,0.7,False,NETWORK,2026-01-01\n"
        "CVE-2026-0006,HIGH,8.5,0.25,0.75,False,NETWORK,2026-01-01\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0005,["RCE in IOS XE"],["CWE-78"],'
        '["cpe:2.3:o:cisco:ios_xe:17.0:*:*:*:*:*:*:*"]\n'
        'CVE-2026-0006,["Buffer overflow in Apache HTTP"],["CWE-120"],'
        '["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
        "CVE-2026-0005,Cisco,IOS XE,2026-01-05,Known,CWE-78\n"
        "CVE-2026-0006,Apache Software Foundation,HTTP Server,2026-01-05,Known,CWE-120\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [
                {"cve": "CVE-2026-0005", "epss": 0.6, "percentile": 0.88},
                {"cve": "CVE-2026-0006", "epss": 0.65, "percentile": 0.92},
            ]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    # Both CVEs are in KEV catalog but neither is Microsoft-scoped
    # Regression: previously both were included due to kev_flag=True; they should now be excluded
    assert len(result) == 0, "Non-Microsoft KEV vendors (Cisco, Apache) should be excluded from scope"


def test_scope_filter_excludes_vendor_matched_only_via_product_name(tmp_path):
    """Verify scope filter checks vendor only, not product — a non-Microsoft vendor
    whose product name happens to contain a Microsoft alias substring (e.g. Oracle's
    "MySQL Server" matching the "sql server" alias) must still be excluded."""
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0007,HIGH,7.5,0.3,0.6,False,NETWORK,2026-01-01\n"
    )
    (kaggle_dir / "cve_corpus.csv").write_text(
        "cve_id,description_data,cwe_data,cpe_data\n"
        'CVE-2026-0007,["SQL injection in MySQL Server"],["CWE-89"],'
        '["cpe:2.3:a:oracle:mysql_server:8.0:*:*:*:*:*:*:*"]\n'
    )
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
        "CVE-2026-0007,Oracle,MySQL Server,2026-01-05,Known,CWE-89\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [{"cve": "CVE-2026-0007", "epss": 0.3, "percentile": 0.6}]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    assert len(result) == 0, (
        "Oracle vendor with product 'MySQL Server' must be excluded despite the "
        "product name colliding with the 'sql server' alias"
    )


def test_scope_filter_scans_all_cpes_not_just_first(tmp_path):
    """Verify a CVE with multiple CPEs is included when the Microsoft CPE is not
    the first entry — the schema rule is "a CPE vendor token matches" (any), not
    specifically index 0."""
    kaggle_dir = tmp_path / "kaggle merged dataset"
    kaggle_dir.mkdir()
    (kaggle_dir / "cve_cisa_epss_enriched_dataset.csv").write_text(
        "cve_id,base_severity,base_score,epss_score,epss_perc,cisa_kev,"
        "attack_vector,published_date\n"
        "CVE-2026-0008,HIGH,8.1,0.4,0.7,False,NETWORK,2026-01-01\n"
    )
    cpe_list = str([
        "cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*",
    ])
    pd.DataFrame([{
        "cve_id": "CVE-2026-0008",
        "description_data": '["RCE affecting Linux kernel and Exchange Server"]',
        "cwe_data": '["CWE-502"]',
        "cpe_data": cpe_list,
    }]).to_csv(kaggle_dir / "cve_corpus.csv", index=False)
    kev_path = tmp_path / "kev_catalog.csv"
    kev_path.write_text(
        "cveID,vendorProject,product,dateAdded,knownRansomwareCampaignUse,cwes\n"
    )
    epss_dir = tmp_path / "epss"
    epss_dir.mkdir()
    epss_path = epss_dir / "epss_scores-2026-08-10.csv.gz"
    epss_path.write_bytes(
        pd.DataFrame(
            [{"cve": "CVE-2026-0008", "epss": 0.4, "percentile": 0.7}]
        ).to_csv(index=False).encode()
    )

    result = build_microsoft_cve_master(kaggle_dir, kev_path, str(epss_dir / "epss_scores-*.csv.gz"))

    assert len(result) == 1, "CVE with Microsoft CPE listed second should still be included"
    row = result.iloc[0]
    assert row["vendor"] == "microsoft"
    assert row["product"] == "exchange server"
