from config.logging import get_logger
from graph.client import Neo4jClient
from graph.writer import write_graph
from ingestion.embedder import embed_techniques
from .loader import load_stix
from .parser import parse_all_stix_bundles
from .mapper import map_all

logger = get_logger(__name__)

def run_stix_pipeline() -> dict:
    logger.info("Starting STIX ingestion pipeline...")
    bundles = load_stix()
    techniques, groups, relationships = parse_all_stix_bundles(bundles)
    mapped = map_all(techniques, groups, relationships)
    logger.info(
        "Mapped %d nodes, %d relationships — writing to Neo4j...",
        len(mapped["nodes"]),
        len(mapped["relationships"]),
    )
    with Neo4jClient() as client:
        counts = write_graph(client, mapped)
        embedded = embed_techniques(client)
    logger.info(
        "STIX pipeline complete — %d nodes, %d relationships persisted, %d embeddings generated",
        counts["nodes"],
        counts["relationships"],
        embedded,
    )
    counts["embedded"] = embedded
    return counts