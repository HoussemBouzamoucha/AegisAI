# File: ai_agent/agent/analyst.py
#
# LangChain chain: correlate_result dict → AgentVerdict
#
# Uses OpenRouter as the API gateway with the poolside/laguna-xs.2:free model.
# OpenRouter exposes an OpenAI-compatible endpoint, so we use ChatOpenAI with
# a custom base_url.
#
# Chain structure:
#
#   build_prompt_context(result)       ← extract threat-relevant slice
#         │
#         ▼
#   PROMPT (ChatPromptTemplate)        ← format system + human messages
#         │
#         ▼
#   ChatOpenAI (OpenRouter)            ← poolside/laguna-xs.2:free, temperature=0
#         │
#         ▼
#   _extract_text(response)            ← handles str | list content blocks
#         │
#         ▼
#   _parse_verdict(text)               ← strip fences, Pydantic validate
#         │
#         ▼
#   AgentVerdict (validated, typed)

import json
import os
import sys

from langchain_openai import ChatOpenAI

from .prompt import PROMPT, build_prompt_context
from .schema import AgentVerdict

# ─── Constants ────────────────────────────────────────────────────────────────

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
MODEL               = "poolside/laguna-xs.2:free"


# ─── Content extractor ────────────────────────────────────────────────────────

def _extract_text(response) -> str:
    """
    Extract plain text from a LangChain AIMessage response.

    In langchain-openai 1.x / openai 2.x the `.content` field can be:
      - str                    (most models, simple text response)
      - list[str | dict]       (content-block format used by some models)
        each dict looks like:  {"type": "text", "text": "..."}

    Returns the concatenated text, or raises ValueError if nothing was found.
    """
    content = response.content

    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                # {"type": "text", "text": "..."} or {"type": "output_text", "text": "..."}
                parts.append(block.get("text") or block.get("output_text") or "")
        text = "".join(parts)
    else:
        text = str(content)

    text = text.strip()
    if not text:
        # Log the full response object so we can debug what the model returned
        print(f"[agent] WARNING: empty content. Full response: {response!r}", file=sys.stderr)
        raise ValueError(
            f"Model returned empty content.\n"
            f"Response type: {type(content)}\n"
            f"Response repr: {response!r}"
        )

    return text


# ─── Response parser ──────────────────────────────────────────────────────────

def _extract_json_object(text: str) -> str:
    """
    Find the outermost JSON object `{ ... }` anywhere in the text.

    Models sometimes prepend a heading or explanation before the JSON block.
    This function locates the first `{`, then walks forward tracking brace depth
    to find its matching `}`, and returns that substring.

    Raises ValueError if no balanced JSON object is found.
    """
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model response.")

    depth = 0
    in_string = False
    escape_next = False

    for i, ch in enumerate(text[start:], start=start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    raise ValueError(
        f"Unbalanced braces in model response — JSON object not closed.\n\nRaw text:\n{text}"
    )


def _parse_verdict(text: str) -> AgentVerdict:
    """
    Parse the model's text output into a validated AgentVerdict.

    Handles:
      - Plain JSON
      - JSON wrapped in ```json ... ``` fences
      - JSON preceded by headings/prose (e.g. "## Structured Verdict\\n\\n```json...")
    """
    try:
        json_str = _extract_json_object(text)
        return AgentVerdict.model_validate(json.loads(json_str))
    except (json.JSONDecodeError, Exception) as exc:
        raise ValueError(
            f"Failed to parse AgentVerdict: {exc}\n\nRaw text:\n{text}"
        ) from exc


# ─── Chain builder ────────────────────────────────────────────────────────────

def build_chain():
    """
    Build and return the LangChain analyst chain.

    The chain is stateless and safe to reuse across calls.

    Raises EnvironmentError if OPENROUTER_API_KEY is not set.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENROUTER_API_KEY environment variable is not set. "
            "Add it to ai_agent/.env or export it in your shell."
        )

    llm = ChatOpenAI(
        model=MODEL,
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        temperature=0,
        max_tokens=4096,
        model_kwargs={"response_format": {"type": "json_object"}},
        default_headers={
            "HTTP-Referer": "https://github.com/AegisAI",
            "X-Title":      "AegisAI Threat Analyst",
        },
    )

    # Chain: prompt → LLM  (returns AIMessage)
    chain = PROMPT | llm
    return chain


# ─── Entry point ──────────────────────────────────────────────────────────────

def analyze(correlate_result: dict) -> AgentVerdict:
    """
    Run Round 1 analysis on a correlate result.

    Args:
        correlate_result: The full dict returned by the Rust daemon's
                          `correlate` command (attack_chains, critical_path,
                          nodes, edges, statistics).

    Returns:
        AgentVerdict with ranked_actions, rationale, risk_level, confidence,
        and pivot_suggestions.

    Raises:
        EnvironmentError: OPENROUTER_API_KEY not set.
        ValueError:       Empty/unparseable model response.
    """
    chain    = build_chain()
    context  = build_prompt_context(correlate_result)
    response = chain.invoke(context)

    print(f"[agent] raw response type: {type(response.content)}", file=sys.stderr)
    print(f"[agent] raw content: {response.content!r}", file=sys.stderr)

    text    = _extract_text(response)
    verdict = _parse_verdict(text)
    return verdict
