from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol, Sequence


class RetrievalAdapter(Protocol):
    """Minimal interface that any backend retriever must satisfy."""

    def retrieve(self, query: str, top_k: int) -> list["RetrievedEvidence"]:
        ...


@dataclass(slots=True)
class RetrievedEvidence:
    """A single relevant fact returned by one retrieval backend."""

    id: str
    title: str
    text: str
    source: str
    score: float = 0.0
    entity_type: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RetrievedResult:
    """A fused result containing the evidence set for a query."""

    query: str
    evidence: list[RetrievedEvidence]
    combined_score: float
    rank: int = 0
    reason: str = ""


class HybridRetriever:
    """Combines graph, vector, and BM25 retrieval into a single ranked result set."""

    def __init__(
        self,
        graph_retriever: RetrievalAdapter | None = None,
        vector_retriever: RetrievalAdapter | None = None,
        bm25_retriever: RetrievalAdapter | None = None,
        reranker: Callable[[Sequence[RetrievedEvidence]], Sequence[RetrievedEvidence]] | None = None,
    ) -> None:
        self.graph_retriever = graph_retriever
        self.vector_retriever = vector_retriever
        self.bm25_retriever = bm25_retriever
        self.reranker = reranker

    def retrieve(self, query: str, top_k: int = 10) -> list[RetrievedResult]:
        """Run each backend, fuse the rankings, and return the strongest candidates."""
        if not query or not query.strip():
            return []

        backend_results: list[list[RetrievedEvidence]] = []

        if self.graph_retriever is not None:
            backend_results.append(self.graph_retriever.retrieve(query, top_k))
        if self.vector_retriever is not None:
            backend_results.append(self.vector_retriever.retrieve(query, top_k))
        if self.bm25_retriever is not None:
            backend_results.append(self.bm25_retriever.retrieve(query, top_k))

        if not backend_results:
            return []

        merged = self._fuse_backend_results(query, backend_results)
        if self.reranker is not None:
            merged = list(self.reranker(merged))

        ranked = [
            RetrievedResult(
                query=query,
                evidence=result[1],
                combined_score=result[0],
                rank=index,
                reason=self._explain_result(result[1]),
            )
            for index, result in enumerate(sorted(
                merged,
                key=lambda item: item[0],
                reverse=True,
            )[:top_k])
        ]

        return ranked

    def _fuse_backend_results(
        self,
        query: str,
        backend_results: Sequence[Sequence[RetrievedEvidence]],
    ) -> list[tuple[float, list[RetrievedEvidence]]]:
        """Combine diverse backend rankings by deduplicating overlap and reweighting scores."""
        deduped: dict[str, RetrievedEvidence] = {}
        for results in backend_results:
            for item in results:
                key = item.id or f"{item.source}:{item.title}:{item.text[:80]}"
                existing = deduped.get(key)
                if existing is None:
                    deduped[key] = item
                    continue

                existing.score += item.score
                existing.metadata.update(item.metadata)

        normalized = []
        for item in deduped.values():
            if item.score <= 0:
                continue
            normalized.append(item)

        normalized.sort(key=lambda item: item.score, reverse=True)

        fused: list[tuple[float, list[RetrievedEvidence]]] = []
        for index, item in enumerate(normalized[:max(5, len(normalized))]):
            cluster: list[RetrievedEvidence] = [item]
            for other in normalized[index + 1:]:
                if self._same_entity(item, other):
                    cluster.append(other)
            fused.append((self._aggregate_cluster_score(cluster), cluster))

        return fused

    def _same_entity(self, left: RetrievedEvidence, right: RetrievedEvidence) -> bool:
        if left.entity_type and right.entity_type and left.entity_type != right.entity_type:
            return False

        if left.id and right.id:
            return left.id == right.id

        return left.title == right.title and left.source == right.source

    def _aggregate_cluster_score(self, cluster: Sequence[RetrievedEvidence]) -> float:
        if not cluster:
            return 0.0
        return sum(item.score for item in cluster) / len(cluster)

    def _explain_result(self, evidence: Sequence[RetrievedEvidence]) -> str:
        if not evidence:
            return "No evidence matched the query."

        top = evidence[0]
        return (
            f"Strongest match: {top.title} from {top.source} "
            f"with score {top.score:.3f}."
        )

    def _build_context(self, results: Sequence[RetrievedResult], max_items: int = 8) -> str:
        """Create a compact text block for downstream reasoning."""
        selected = list(results)[:max_items]
        if not selected:
            return "No relevant context available."

        blocks: list[str] = []
        for result in selected:
            parts = [f"Title: {item.title}" for item in result.evidence[:3]]
            text = "\n".join(parts)
            blocks.append(f"[{result.rank}] {text}")

        return "\n\n".join(blocks)


__all__ = [
    "HybridRetriever",
    "RetrievedEvidence",
    "RetrievedResult",
    "RetrievalAdapter",
]
