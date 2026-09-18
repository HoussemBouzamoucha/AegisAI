from neo4j import GraphDatabase, Driver
from config.logging import get_logger
from config.settings import settings

logger = get_logger(__name__)


class Neo4jClient:
    def __init__(self):
        self._driver: Driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        logger.info("Neo4j driver created — %s", settings.neo4j_uri)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self._driver.close()
        logger.info("Neo4j driver closed")

    def verify_connectivity(self):
        self._driver.verify_connectivity()
        logger.info("Neo4j connectivity verified")

    def run(self, query: str, parameters: dict = None) -> list[dict]:
        with self._driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]
