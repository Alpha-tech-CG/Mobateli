"""Risk explanation (cahier §5.6, §17).

Deterministic templates by default. When ANTHROPIC_API_KEY is set, the finding
is enriched with a clearer, context-aware explanation via Claude — used only
for explanation and triage, never for the security decision itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    severity: str
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    rule_id: str | None = None
    remediation: str | None = None


def deterministic_explanation(f: Finding) -> str:
    where = ""
    if f.file_path:
        where = f" ({f.file_path}:{f.line})" if f.line else f" ({f.file_path})"
    fix = f" Correctif recommandé : {f.remediation}" if f.remediation else ""
    return f"{f.title}{where}. {f.description}{fix}"


def explain(f: Finding) -> dict[str, str]:
    """Return a plain-language explanation and remediation for a finding."""
    base = deterministic_explanation(f)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"explanation": base, "source": "deterministic"}

    try:
        from anthropic import Anthropic

        client = Anthropic(api_key=api_key)
        prompt = (
            "Explique ce problème de sécurité à un développeur non spécialiste, "
            "en 2-3 phrases claires, sans jargon, puis donne le correctif concret.\n\n"
            f"Titre: {f.title}\nSévérité: {f.severity}\nDétail: {f.description}\n"
            f"Règle: {f.rule_id}\n"
        )
        msg = client.messages.create(
            model="claude-haiku-5-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in msg.content if block.type == "text")
        return {"explanation": text.strip() or base, "source": "claude"}
    except Exception:
        # Never let the LLM path break the product — fall back to deterministic.
        return {"explanation": base, "source": "deterministic_fallback"}
