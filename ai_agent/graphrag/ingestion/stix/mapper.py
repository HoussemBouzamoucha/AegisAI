from .parser import STIXTechnique, STIXGroup, STIXRelationship


def map_technique(technique: STIXTechnique) -> dict:
    return {
        "label": "Technique",
        "properties": {
            "stix_id": technique.stix_id,
            "technique_id": technique.technique_id,
            "name": technique.name,
            "description": technique.description,
            "platforms": technique.platforms,
            "tactic_phases": technique.tactic_phases,
            "is_subtechnique": technique.is_subtechnique,
        },
    }
def map_group(group: STIXGroup) -> dict:
    return {
        "label": "Group",
        "properties": {
            "stix_id": group.stix_id,
            "name": group.name,
            "description": group.description,
            "aliases": group.aliases,
        },
    }


def map_relationship(relationship: STIXRelationship) -> dict:
    return {
        "source_ref": relationship.source_ref,
        "target_ref": relationship.target_ref,
        "relationship_type": relationship.relationship_type.upper().replace("-", "_"),
        "properties": {
            "stix_id": relationship.stix_id,
            "description": relationship.description,
        },
    }


def map_all(
    techniques: list[STIXTechnique],
    groups: list[STIXGroup],
    relationships: list[STIXRelationship],
) -> dict:
    return {
        "nodes": [map_technique(t) for t in techniques] + [map_group(g) for g in groups],
        "relationships": [map_relationship(r) for r in relationships],
    }