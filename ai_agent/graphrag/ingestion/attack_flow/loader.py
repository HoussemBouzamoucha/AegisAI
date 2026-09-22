import json
import zipfile
from pathlib import Path
from config.logging import get_logger
from config.settings import settings

logger = get_logger(__name__)

def load_afb_file(file_path: Path) -> dict | None:
    try:
        with zipfile.ZipFile(file_path) as zf:
            with zf.open(zf.namelist()[0]) as f:
                data = json.load(f)
        logger.info("Loaded AFB file: %s", file_path.name)
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", file_path.name, e)
        return None

def load_flow() -> list[dict]:
    flow_dir = settings.data_dir / "corpus"
    afb_files = list(flow_dir.glob("*.afb"))
    if not afb_files:
        logger.warning("No AFB files found in: %s", flow_dir)
        return []
    
    flows = []
    for file_path in afb_files:
        flow = load_afb_file(file_path)
        if flow is not None:
            flows.append(flow)
    logger.info("Loaded %d AFB flow(s) in total.", len(flows))
    return flows