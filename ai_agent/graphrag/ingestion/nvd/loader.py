import json
from pathlib import Path
from config.logging import get_logger
from config.settings import settings


logger = get_logger(__name__)

def load_nvd_file(file_path: Path) -> dict | None:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Loaded NVD file: %s", file_path.name)
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", file_path.name, e)
        return None
    
    
def load_nvd_from_api():
    # Placeholder for future implementation to load NVD data from API
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key = settings.nvd_api_key
    request_url = f"{base_url}?apiKey={api_key}"
    request_params = {
        "resultsPerPage": 1000,
        "startIndex": 0,
        "pubStartDate": "2023-01-01T00:00:00:000 UTC-05:00",
        "pubEndDate": "2026-9-31T23:59:59:999 UTC-05:00",
    }
    logger.info("Loading NVD data from API is not yet implemented.")
    return []