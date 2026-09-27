from dataclasses import dataclass, field
from typing import Any

from config.logging import get_logger

logger = get_logger(__name__)


@dataclass
class NVDCVE:
	cve_id: str
	description: str | None = None
	cvss_score: float | None = None
	cvss_severity: str | None = None
	published: str | None = None
	last_modified: str | None = None
	cwe_ids: list[str] = field(default_factory=list)
	affected_cpes: list[str] = field(default_factory=list)


def _description(cve: dict[str, Any]) -> str | None:
	descriptions = cve.get("descriptions", [])
	for item in descriptions:
		if item.get("lang") == "en" and item.get("value"):
			return item["value"]
	return next(
		(item.get("value") for item in descriptions if item.get("value")),
		None,
	)


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
	metrics = cve.get("metrics", {})
	for metric_name in ("cvssMetricV4", "cvssMetricV3", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
		entries = metrics.get(metric_name, [])
		if not entries:
			continue
		metric = entries[0].get("cvssData", {})
		return metric.get("baseScore"), metric.get("baseSeverity")
	return None, None


def _cwe_ids(cve: dict[str, Any]) -> list[str]:
	identifiers: list[str] = []
	for weakness in cve.get("weaknesses", []):
		for description in weakness.get("description", []):
			value = description.get("value")
			if value and value not in identifiers:
				identifiers.append(value)
	return identifiers


def _affected_cpes(cve: dict[str, Any]) -> list[str]:
	cpes: list[str] = []

	def visit(node: dict[str, Any]) -> None:
		for match in node.get("cpeMatch", []):
			criteria = match.get("criteria")
			if criteria and criteria not in cpes:
				cpes.append(criteria)
		for child in node.get("children", []):
			visit(child)

	for configuration in cve.get("configurations", []):
		for node in configuration.get("nodes", []):
			visit(node)
	return cpes


def parse_cve(item: dict[str, Any]) -> NVDCVE | None:
	cve = item.get("cve", item)
	cve_id = cve.get("id")
	if not cve_id:
		logger.warning("Skipping NVD record without a CVE id")
		return None

	score, severity = _cvss(cve)
	return NVDCVE(
		cve_id=cve_id,
		description=_description(cve),
		cvss_score=score,
		cvss_severity=severity,
		published=cve.get("published"),
		last_modified=cve.get("lastModified"),
		cwe_ids=_cwe_ids(cve),
		affected_cpes=_affected_cpes(cve),
	)


def parse_nvd_response(response: dict[str, Any]) -> list[NVDCVE]:
	vulnerabilities = response.get("vulnerabilities", [])
	parsed = [parse_cve(item) for item in vulnerabilities]
	records = [record for record in parsed if record is not None]
	logger.info("Parsed %d NVD CVE record(s)", len(records))
	return records
