from unittest.mock import MagicMock

from dashboard._data_sources_queries import (
    INSTALLED_SOFTWARE_EXAMPLE_QUERY,
    KEV_COUNT_QUERY,
    SAMPLE_CVE_ROWS_QUERY,
    SEVERITY_BREAKDOWN_QUERY,
    TOP_PRODUCTS_QUERY,
    TOTAL_CVE_COUNT_QUERY,
    read_cve_stats,
    read_installed_software_example,
    read_sample_cve_rows,
    read_severity_breakdown,
    read_top_products,
)


def test_sample_cve_rows_query_guarantees_one_kev_true_and_kev_false():
    assert "kev_flag = true" in SAMPLE_CVE_ROWS_QUERY
    assert "kev_flag = false" in SAMPLE_CVE_ROWS_QUERY
    assert "UNION" in SAMPLE_CVE_ROWS_QUERY


def test_top_products_query_limits_to_ten_ordered_by_count():
    assert "ORDER BY count DESC" in TOP_PRODUCTS_QUERY
    assert "LIMIT 10" in TOP_PRODUCTS_QUERY


def test_read_sample_cve_rows_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"cve_id": "CVE-2021-1111", "kev_flag": True}, {"cve_id": "CVE-2021-2222", "kev_flag": False}]
    session.run.return_value = rows

    result = read_sample_cve_rows(session)

    assert result == rows
    session.run.assert_called_once_with(SAMPLE_CVE_ROWS_QUERY)


def test_read_cve_stats_runs_both_count_queries():
    session = MagicMock()
    session.run.return_value.single.side_effect = [{"n": 26285}, {"n": 1200}]

    result = read_cve_stats(session)

    assert result == {"total": 26285, "kev_count": 1200}
    assert session.run.call_args_list == [((TOTAL_CVE_COUNT_QUERY,),), ((KEV_COUNT_QUERY,),)]


def test_read_severity_breakdown_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"severity": "HIGH", "count": 500}, {"severity": "LOW", "count": 200}]
    session.run.return_value = rows

    result = read_severity_breakdown(session)

    assert result == rows
    session.run.assert_called_once_with(SEVERITY_BREAKDOWN_QUERY)


def test_read_top_products_runs_query_and_returns_rows():
    session = MagicMock()
    rows = [{"product": "windows 10", "count": 300}]
    session.run.return_value = rows

    result = read_top_products(session)

    assert result == rows
    session.run.assert_called_once_with(TOP_PRODUCTS_QUERY)


def test_read_installed_software_example_returns_first_row_or_none():
    session = MagicMock()
    session.run.return_value = [{"asset_id": "computer-0001", "cve_id": "CVE-2021-1111"}]

    result = read_installed_software_example(session)

    assert result == {"asset_id": "computer-0001", "cve_id": "CVE-2021-1111"}
    session.run.assert_called_once_with(INSTALLED_SOFTWARE_EXAMPLE_QUERY)


def test_read_installed_software_example_returns_none_when_no_rows():
    session = MagicMock()
    session.run.return_value = []

    result = read_installed_software_example(session)

    assert result is None
