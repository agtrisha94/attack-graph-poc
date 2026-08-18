"""Builds the local RAG index for the chatbot: chunks MITRE ATT&CK
technique/mitigation/threat-actor descriptions, embeds them locally, and
saves the result to data/rag_index.npz for brute-force cosine-similarity
retrieval at query time (see dashboard/_rag_retriever.py). Rerun when
data/raw/mitre-cti changes."""
import json
import pathlib

import numpy as np
from sentence_transformers import SentenceTransformer

STIX_PATH = pathlib.Path("data/raw/mitre-cti/enterprise-attack/enterprise-attack.json")
INDEX_PATH = pathlib.Path("data/rag_index.npz")
MODEL_NAME = "all-MiniLM-L6-v2"  # must match dashboard/_rag_retriever.py

_SOURCE_TYPE_BY_STIX_TYPE = {
    "attack-pattern": "technique",
    "course-of-action": "mitigation",
    "intrusion-set": "threat_actor",
}


def _external_id(obj: dict) -> str | None:
    return next(
        (r["external_id"] for r in obj.get("external_references", [])
         if r.get("source_name") == "mitre-attack"),
        None,
    )


def build_chunks(stix_path: pathlib.Path = STIX_PATH) -> list[dict]:
    objects = json.loads(stix_path.read_text())["objects"]

    chunks = []
    for obj in objects:
        source_type = _SOURCE_TYPE_BY_STIX_TYPE.get(obj.get("type"))
        if not source_type or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        name, description = obj.get("name"), obj.get("description")
        if not name or not description:
            continue
        chunks.append({
            "id": _external_id(obj) or name,
            "source_type": source_type,
            "name": name,
            "text": f"{name}: {description}",
        })
    return chunks


def main() -> None:
    chunks = build_chunks()
    model = SentenceTransformer(MODEL_NAME)
    embeddings = model.encode(
        [c["text"] for c in chunks], show_progress_bar=True, normalize_embeddings=True,
    )
    np.savez(
        INDEX_PATH,
        embeddings=np.asarray(embeddings, dtype=np.float32),
        ids=np.array([c["id"] for c in chunks], dtype=object),
        source_types=np.array([c["source_type"] for c in chunks], dtype=object),
        names=np.array([c["name"] for c in chunks], dtype=object),
        texts=np.array([c["text"] for c in chunks], dtype=object),
    )
    print(f"Indexed {len(chunks)} chunk(s) -> {INDEX_PATH}")


if __name__ == "__main__":
    main()
