import logging
from config.settings import settings

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.getLevelName(settings.log_level),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler()],
    )

def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
