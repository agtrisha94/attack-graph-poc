import numpy as np

from dashboard._rag_retriever import exact_id_indices, top_k_indices


def test_exact_id_indices_finds_literal_id_in_question():
    ids = np.array(["T1078", "T1566", "M1032"], dtype=object)

    assert exact_id_indices("What is T1078?", ids) == [0]


def test_exact_id_indices_returns_empty_list_when_no_id_in_question():
    ids = np.array(["T1078", "T1566"], dtype=object)

    assert exact_id_indices("What's our riskiest attack path?", ids) == []


def test_exact_id_indices_is_case_insensitive():
    ids = np.array(["T1078"], dtype=object)

    assert exact_id_indices("tell me about t1078", ids) == [0]


def test_top_k_indices_ranks_by_descending_similarity():
    query = np.array([1.0, 0.0])
    embeddings = np.array([
        [0.0, 1.0],   # orthogonal -> lowest
        [1.0, 0.0],   # identical -> highest
        [0.7, 0.7],   # partial match -> middle
    ])

    result = top_k_indices(query, embeddings, k=3)

    assert list(result) == [1, 2, 0]


def test_top_k_indices_respects_k():
    query = np.array([1.0, 0.0])
    embeddings = np.array([[1.0, 0.0], [0.9, 0.1], [0.0, 1.0]])

    result = top_k_indices(query, embeddings, k=2)

    assert list(result) == [0, 1]
