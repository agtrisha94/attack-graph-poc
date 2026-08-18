from dashboard._glossary import GLOSSARY, relevant_glossary_entries


def test_relevant_glossary_entries_matches_choke_point_alias():
    result = relevant_glossary_entries("why is this asset a choke point?")

    assert [e["term"] for e in result] == ["choke_point"]


def test_relevant_glossary_entries_is_case_insensitive():
    result = relevant_glossary_entries("What is a CVE?")

    assert any(e["term"] == "cve" for e in result)


def test_relevant_glossary_entries_matches_multiple_terms():
    result = relevant_glossary_entries("How does CVSS relate to EPSS?")

    terms = {e["term"] for e in result}
    assert {"cvss", "epss"}.issubset(terms)


def test_relevant_glossary_entries_returns_empty_list_when_nothing_matches():
    assert relevant_glossary_entries("what's the weather like today?") == []


def test_relevant_glossary_entries_returns_term_and_scope_alongside_definition():
    result = relevant_glossary_entries("what is a CVE?")

    entry = next(e for e in result if e["term"] == "cve")
    assert entry["scope"] == "general"
    assert "definition" in entry


def test_every_app_specific_entry_frames_itself_as_this_apps_own_choice():
    for term, entry in GLOSSARY.items():
        if entry["scope"] == "app_specific":
            assert "this app" in entry["definition"].lower(), (
                f"{term} is app_specific but its definition doesn't say 'this app' anywhere"
            )


def test_scoring_formula_entry_explicitly_disclaims_being_a_generic_rule():
    entry = GLOSSARY["attack_path_score"]
    assert entry["scope"] == "app_specific"
    assert "not" in entry["definition"].lower()
    assert "industry-standard" in entry["definition"].lower() or "generic" in entry["definition"].lower()
