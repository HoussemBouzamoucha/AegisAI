from itertools import islice
from config.logging import get_logger
from .client import Neo4jClient

logger = get_logger(__name__)
_BATCH_SIZE = 500
#helper function
def _chunks(lst,size):
    it=iter(lst)
    while True:
        chunk=list(islice(it,size))
        if not chunk:
            break
        yield chunk
        
        
_NODE_QUERIES:dict[str,str]={
    "Technique": """
    UNWIND $rows AS row
    MERGE (t:Technique {stix_id: row.stix_id})
    SET 
        t.technique_id=row.technique_id,
        t.name=row.name,
        t.platforms=row.platforms,
        t.tactic_phases=row.tactic_phases,
        t.is_subtechnique=row.is_subtechnique
        
    """,
    "Group": """
    UNWIND $rows AS row
    MERGE (g:Group {stix_id: row.stix_id})
    SET 
        g.name=row.name,
        g.description=row.description,
        g.aliases=row.aliases
        
    """,
    "AttackFlow":"""
    UNWIND $rows AS row
    MERGE (a:AttackFlow {flow_id: row.flow_id})
    SET
        a.name=row.name,
        a.description=row.description,
        a.created=row.created
        
    """,
    "Vulnerability":"""
    UNWIND $rows AS row
    MERGE (v:Vulnerability {cve_id: row.cve_id})
    SET
        v.description=row.description,
        v.cvss_score=row.cvss_score,
        v.cvss_severity=row.cvss_severity,
        v.published=row.published,
        v.last_modified=row.last_modified,
        v.cwe_ids=row.cwe_ids,
        v.affected_cpes=row.affected_cpes

    """,
    
}

def write_nodes(
    client: Neo4jClient,
    nodes: list[dict],
    batch_size: int = _BATCH_SIZE,
) -> int:
    by_label: dict[str, list[dict]] = {}
    for node in nodes:
        label=node["label"]
        by_label.setdefault(label,[]).append(node["properties"])
    
    total=0
    for label,rows in by_label.items():
        query=_NODE_QUERIES.get(label)
        if query is None:
            logger.warning(
                "No write query registered for label '%s' — skipping %d nodes",
                label,len(rows),
            )
            continue
        
        for chunk in _chunks(rows,batch_size):
            client.run(query,{"rows":chunk})
            total+=len(chunk)
        logger.debug("wrote %d '%s' nodes",len(rows),label)
    return total
    
#Relationship wwriter
_REL_QUERY_TEMPLATE ="""
UNWIND $rows AS row
MATCH (src {{stix_id:row.source_ref}})
MATCH (tgt {{stix_id:row.target_ref}})
MERGE (src)-[r:{rel_type}]->(tgt)
SET r+=row.properties

"""
def write_relationships(
    client: Neo4jClient,
    relationships: list[dict],
    batch_size: int = _BATCH_SIZE,
) -> int:
    by_type: dict[str, list[dict]] = {}
    for rel in relationships:
        rel_type = rel["relationship_type"]
        by_type.setdefault(rel_type, []).append(rel)

    total = 0
    for rel_type, rels in by_type.items():
        query = _REL_QUERY_TEMPLATE.format(rel_type=rel_type)
        for chunk in _chunks(rels, batch_size):
            client.run(query, {"rows": chunk})
            total += len(chunk)

        logger.debug("Wrote %d '%s' relationships", len(rels), rel_type)

    return total


  # ---------------------------------------------------------------------------
  # Top-level entry point
  # ---------------------------------------------------------------------------

def write_graph(
    client: Neo4jClient,
    mapped: dict,
    batch_size: int = _BATCH_SIZE,
) -> dict[str, int]:
    nodes_written = write_nodes(client, mapped.get("nodes", []), batch_size)
    rels_written  = write_relationships(client, mapped.get("relationships", []),
  batch_size)

    logger.info(
        "write_graph complete — %d nodes, %d relationships persisted",
        nodes_written, rels_written,
    )
    return {"nodes": nodes_written, "relationships": rels_written}