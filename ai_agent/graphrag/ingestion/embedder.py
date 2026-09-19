from itertools import islice
from sentence_transformers import SentenceTransformer
from config.logging import get_logger
from config.settings import settings
from graph.client import Neo4jClient

logger = get_logger(__name__)

_BATCH_SIZE = 500

_FETCH_QUERY = """
MATCH (t:Technique)
WHERE t.embedding IS NULL
RETURN t.stix_id AS stix_id, t.name AS name, t.description AS description
"""

_WRITE_QUERY = """
UNWIND $rows AS row
MATCH (t:Technique {stix_id: row.stix_id})
SET t.embedding = row.embedding
"""


def _chunks(lst: list, size: int):
    it = iter(lst)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


def embed_techniques(client: Neo4jClient) -> int:
    """
    Fetch all Technique nodes with no embedding, generate vectors,
    and write them back to Neo4j.

    Returns the number of nodes embedded.
    """
    rows = client.run(_FETCH_QUERY)
    if not rows:
        logger.info("No unembedded techniques found — skipping")
        return 0

    logger.info("Embedding %d techniques with model '%s'", len(rows), settings.embedding_model)

    # Build one text string per node — description may be None
    texts = [
        f"{row['name']}. {row['description'] or ''}".strip()
        for row in rows
    ]

    # Load model and encode all texts in one batch call
    model = SentenceTransformer(settings.embedding_model)
    vectors = model.encode(texts, show_progress_bar=True)

    # Pair each stix_id with its vector and write back in batches
    payload = [
        {"stix_id": row["stix_id"], "embedding": vec.tolist()}
        for row, vec in zip(rows, vectors)
    ]

    for chunk in _chunks(payload, _BATCH_SIZE):
        client.run(_WRITE_QUERY, {"rows": chunk})

    logger.info("Embedded %d techniques", len(payload))
    return len(payload)
