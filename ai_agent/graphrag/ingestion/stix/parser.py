from dataclasses import dataclass, field
from typing import List, Optional
from config.logging import get_logger

logger = get_logger(__name__)

@dataclass
class STIXTechnique:
    stix_id: str
    technique_id: str
    name: str
    platforms: List[str] = field(default_factory=list)
    tactic_phases: List[str] = field(default_factory=list)
    is_subtechnique: bool = False
    description: Optional[str] = None

@dataclass
class STIXGroup:
    stix_id: str
    name: str
    description: Optional[str] = None
    aliases: List[str] = field(default_factory=list)

@dataclass
class STIXRelationship:
    stix_id: str
    source_ref: str
    target_ref: str
    relationship_type: str
    description: Optional[str] = None


    
def parse_technique(obj: dict) -> Optional[STIXTechnique]:
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    ext_refs = obj.get("external_references", [])
    technique_id = next(
        (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )

    tactic_phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]

    return STIXTechnique(
        stix_id=obj["id"],
        technique_id=technique_id,
        name=obj["name"],
        description=obj.get("description"),
        platforms=obj.get("x_mitre_platforms", []),
        tactic_phases=tactic_phases,
        is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
    )
def parse_group(obj: dict) -> Optional[STIXGroup]:
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    
    return STIXGroup(
        stix_id=obj["id"],
        name=obj["name"],
        description=obj.get("description"),
        aliases=obj.get("aliases", []),
    )
    
def parse_relationship(obj: dict) -> Optional[STIXRelationship]:
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    return STIXRelationship(
        stix_id=obj["id"],
        source_ref=obj["source_ref"],
        target_ref=obj["target_ref"],
        relationship_type=obj["relationship_type"],
        description=obj.get("description"),
    )

    
def parse_stix_bundle(bundle: dict) -> tuple[List[STIXTechnique], List[STIXGroup], List[STIXRelationship]]:
    techniques: List[STIXTechnique] = []
    groups: List[STIXGroup] = []
    relationships: List[STIXRelationship] = []

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            technique = parse_technique(obj)
            if technique:
                techniques.append(technique)
        elif obj_type == "intrusion-set":
            group = parse_group(obj)
            if group:
                groups.append(group)
        elif obj_type == "relationship":
            relationship = parse_relationship(obj)
            if relationship:
                relationships.append(relationship)

    return techniques, groups, relationships

def parse_all_stix_bundles(bundles: list[dict]) -> tuple[List[STIXTechnique], List[STIXGroup], List[STIXRelationship]]:
    logger.info("Parsing %d STIX bundle(s)", len(bundles))
    all_techniques: List[STIXTechnique] = []
    all_groups: List[STIXGroup] = []
    all_relationships: List[STIXRelationship] = []

    for bundle in bundles:
        techniques, groups, relationships = parse_stix_bundle(bundle)
        all_techniques.extend(techniques)
        all_groups.extend(groups)
        all_relationships.extend(relationships)
    
    
    logger.info("Parsed %d techniques, %d groups, and %d relationships in total.", len(all_techniques), len(all_groups), len(all_relationships))
    return all_techniques, all_groups, all_relationships