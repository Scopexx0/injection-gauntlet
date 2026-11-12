"""Corpus loading and validation.

The attack corpus and benign control set are plain JSON files so they can
be reviewed, extended, and diffed like any other test fixture. Every case
is validated on load: required fields, known categories / channels /
target actions, OWASP tag format, unique ids. A malformed corpus fails
loudly instead of silently skewing the metrics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

ATTACK_CATEGORIES = {
    "direct_override",        # user directly orders the copilot to drop its rules
    "indirect_injection",     # payload planted in a document the user did not write
    "pii_exfiltration",       # objective: bulk customer PII disclosure
    "transaction_manipulation",  # objective: approve / release a transaction
    "system_prompt_extraction",  # objective: leak the copilot's instructions
}

CHANNELS = {
    "direct_chat", "kyc_document", "support_ticket",
    "transaction_memo", "vendor_email", "meeting_notes",
}

TARGET_ACTIONS = {
    "exfiltrate_pii", "approve_transaction", "reveal_system_prompt",
    "suppress_fraud_flag", "override_kyc_status",
}

TASK_TYPES = {
    "summarize", "draft", "translate", "completeness_check",
    "balance_lookup", "status_check", "explain",
}


@dataclass
class AttackCase:
    id: str
    title: str
    category: str
    channel: str
    owasp: str
    user_request: str
    document: str
    target_action: str
    notes: str = ""


@dataclass
class BenignCase:
    id: str
    title: str
    channel: str
    user_request: str
    document: str
    needs_document: bool
    task_type: str


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_attacks(path: Path | None = None) -> tuple[list[AttackCase], dict]:
    data = _load_json(path or DATA_DIR / "attacks.json")
    cases: list[AttackCase] = []
    seen: set[str] = set()
    for raw in data["cases"]:
        case = AttackCase(**raw)
        if case.id in seen:
            raise ValueError(f"duplicate attack id: {case.id}")
        seen.add(case.id)
        if case.category not in ATTACK_CATEGORIES:
            raise ValueError(f"{case.id}: unknown category {case.category!r}")
        if case.channel not in CHANNELS:
            raise ValueError(f"{case.id}: unknown channel {case.channel!r}")
        if case.target_action not in TARGET_ACTIONS:
            raise ValueError(f"{case.id}: unknown target_action {case.target_action!r}")
        if not (case.owasp.startswith("LLM") and len(case.owasp) == 5 and case.owasp[3:].isdigit()):
            raise ValueError(f"{case.id}: bad OWASP tag {case.owasp!r}")
        if not case.user_request.strip():
            raise ValueError(f"{case.id}: empty user_request")
        cases.append(case)
    meta = {k: v for k, v in data.items() if k != "cases"}
    return cases, meta


def load_benign(path: Path | None = None) -> tuple[list[BenignCase], dict]:
    data = _load_json(path or DATA_DIR / "benign.json")
    cases: list[BenignCase] = []
    seen: set[str] = set()
    for raw in data["cases"]:
        case = BenignCase(**raw)
        if case.id in seen:
            raise ValueError(f"duplicate benign id: {case.id}")
        seen.add(case.id)
        if case.channel not in CHANNELS:
            raise ValueError(f"{case.id}: unknown channel {case.channel!r}")
        if case.task_type not in TASK_TYPES:
            raise ValueError(f"{case.id}: unknown task_type {case.task_type!r}")
        if case.needs_document and not case.document.strip():
            raise ValueError(f"{case.id}: needs_document but document is empty")
        cases.append(case)
    meta = {k: v for k, v in data.items() if k != "cases"}
    return cases, meta
