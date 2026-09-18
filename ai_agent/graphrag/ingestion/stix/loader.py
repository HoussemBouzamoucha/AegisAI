import json
from pathlib import Path
from config.logging import get_logger
from .config.settings import settings

logger = get_logger(__name__)

STIX_DIRS = [
    "attack-stix-data-master/enterprise-attack",
    "attack-stix-data-master/ics-attack",
]

def load_stix_file(file_path: Path) -> dict | None:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Loaded STIX file: %s", file_path.name)
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", file_path.name, e)
        return None

def load_stix() -> list[dict]:
    bundles = []
    for subdir in STIX_DIRS:
        folder = settings.data_dir / subdir
        json_files = list(folder.glob("*.json"))
        if not json_files:
            logger.warning("No STIX files found in: %s", folder)
            continue
        for file_path in json_files:
            bundle = load_stix_file(file_path)
            if bundle is not None:
                bundles.append(bundle)
    logger.info("Loaded %d STIX bundle(s) in total.", len(bundles))
    return bundles
