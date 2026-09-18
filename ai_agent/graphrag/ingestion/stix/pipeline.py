from config.logging import get_logger
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
        "Pipeline complete — %d nodes, %d relationships ready for Neo4j",
        len(mapped["nodes"]),
        len(mapped["relationships"]),
    )
    return mapped