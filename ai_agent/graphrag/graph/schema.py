from config.logging import get_logger
from config.settings import settings
from .client import Neo4jClient

logger = get_logger(__name__)

SCHEMA_STATEMENTS = [
    # constraints
    "CREATE CONSTRAINT technique_stix_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.stix_id IS UNIQUE",
    "CREATE CONSTRAINT group_stix_id IF NOT EXISTS FOR (g:Group) REQUIRE g.stix_id IS UNIQUE",
    # lookup index
    "CREATE INDEX technique_id_index IF NOT EXISTS FOR (t:Technique) ON (t.technique_id)",
    # fulltext index for BM25 retrieval
    "CREATE FULLTEXT INDEX technique_fulltext IF NOT EXISTS FOR (t:Technique) ON EACH [t.name, t.description]",
    # vector index for semantic search
    f"""CREATE VECTOR INDEX technique_embedding IF NOT EXISTS
FOR (t:Technique) ON t.embedding
OPTIONS {{indexConfig: {{`vector.dimensions`: {settings.vector_index_dim}, `vector.similarity_function`: 'cosine'}}}}""",
]

def apply_schema(client:Neo4jClient):
    client.verify_connectivity()
    for statement in SCHEMA_STATEMENTS:
        client.run(statement)
        
    logger.info("Schema updated - constraints and indexes are in place")
            
        