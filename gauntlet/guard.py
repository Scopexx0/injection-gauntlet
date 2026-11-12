"""Detection layer for the guarded copilot configuration.

This module vendors the two-layer detection engine from Project #1
("Prompt-Injection Guard", in this same portfolio) so InjectionGauntlet is
fully self-contained and runs offline:

  Layer 1 - heuristic detectors: regex patterns for known injection
            techniques (instruction override, system-prompt extraction,
            role hijack, delimiter escape, fake authority, encoded
            payloads). Each detector contributes its points once.
  Layer 2 - statistical scorer: a Naive-Bayes-style token log-odds scorer.

One deliberate methodology change vs. Project #1: Layer 2 here is trained
ONLY on Project #1's general labeled prompt dataset (vendored as
``data/guard_training.json``), never on this project's finance corpus.
The finance attack corpus is therefore a genuine held-out test for the
statistical layer - the results in the README are not an in-sample
smoke test for Layer 2. (Layer 1's patterns are generic technique
patterns, written before this corpus, in Project #1.)

Combination rule (same as Project #1, kept explainable):
    blended = 0.6 * heuristic + 0.4 * statistical
    final   = max(heuristic, blended)
Thresholds default to flag >= 30, block >= 65.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

TRAINING_DATA = Path(__file__).resolve().parent.parent / "data" / "guard_training.json"

MAX_INPUT_CHARS = 20_000  # inputs longer than this are truncated before scoring


# ---------------------------------------------------------------------------
# Layer 1 - heuristic detectors (vendored from Project #1, unchanged logic)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    detector: str
    reason: str
    points: int


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_RULES: list[tuple[str, int, list[tuple[re.Pattern, str]]]] = [
    (
        "instruction_override",
        75,
        [
            (_rx(r"ignore\s+(all\s+|the\s+)?(previous|prior|preceding|above|earlier)\s+(instructions|prompts?|rules|directions)"),
             "Tells the model to ignore its previous instructions"),
            (_rx(r"disregard\s+(your\s+|all\s+|the\s+)?(system\s+)?(prompt|instructions|rules|guidelines|directions)"),
             "Tells the model to disregard its instructions"),
            (_rx(r"forget\s+(everything|all)\s+(you|that)\s+(were|was)\s+(told|said|given)"),
             "Tells the model to forget what it was told"),
            (_rx(r"forget\s+(your|the)\s+(instructions|rules|programming|guidelines)"),
             "Tells the model to forget its rules"),
            (_rx(r"override\s+(your\s+|the\s+)?(safety\s+)?(settings|instructions|rules|filters?)"),
             "Asks to override safety settings or instructions"),
            (_rx(r"\bignoring\s+all\s+(the\s+)?rules\b"),
             "Contains 'ignoring all rules'"),
        ],
    ),
    (
        "role_hijack",
        65,
        [
            (_rx(r"you\s+are\s+now\s+(a\s+|an\s+|the\s+)?[a-z0-9]"),
             "Reassigns the model a new identity ('you are now ...')"),
            (_rx(r"act\s+as\s+(a\s+|an\s+)?(dan|jailbreak|unrestricted|unfiltered|evil)"),
             "Asks the model to act as an unrestricted persona"),
            (_rx(r"\b(developer|god|admin)\s+mode\b"),
             "Claims a privileged 'mode' (developer/god/admin)"),
            (_rx(r"\bdo\s+anything\s+now\b"),
             "References the 'Do Anything Now' (DAN) jailbreak"),
            (_rx(r"your\s+new\s+persona\s+is"),
             "Assigns a new persona to the model"),
            (_rx(r"pretend\s+(you\s+(are|have)|to\s+be)\b[^.]{0,60}(no\s+rules|no\s+guidelines|unrestricted|without\s+(any\s+)?(rules|limits|restrictions|guidelines))"),
             "Asks the model to pretend it has no rules"),
            (_rx(r"respond\s+as\s+(a\s+|an\s+)?(unrestricted|unfiltered)"),
             "Asks for responses as an unrestricted model"),
        ],
    ),
    (
        "system_prompt_extraction",
        70,
        [
            (_rx(r"(reveal|show|print|repeat|output|display|leak|recite|write|share)\b[^.]{0,40}(system\s+prompt|your\s+instructions|your\s+initial\s+prompt|initial\s+prompt|hidden\s+instructions)"),
             "Asks the model to reveal its system prompt or instructions"),
            (_rx(r"what\s+(are|were)\s+your\s+(exact\s+)?(instructions|system\s+prompt)"),
             "Asks what the model's instructions are"),
            (_rx(r"\binstructions\s+you\s+(were|was)\s+given\b"),
             "Asks for the instructions the model was given"),
            (_rx(r"repeat\s+the\s+(text|words|prompt)\s+above"),
             "Asks the model to repeat the text above (extraction probe)"),
            (_rx(r"(my|your)\s+system\s+prompt\s+is"),
             "Tries to get the model to complete 'my system prompt is...'"),
            (_rx(r"(confidential|hidden|secret)\s+(configuration|instructions|settings|prompt)"),
             "References the model's hidden/confidential configuration"),
        ],
    ),
    (
        "delimiter_escape",
        60,
        [
            (_rx(r"###\s*(system|instruction)"),
             "Injects a fake '### SYSTEM' section delimiter"),
            (_rx(r"<\|im_start\|>|<\|im_end\|>|\[INST\]|<<SYS>>|<</SYS>>|</?system>"),
             "Contains chat-template control tokens (im_start / [INST] / <<SYS>>)"),
            (_rx(r"^\s*(human|assistant|system)\s*:\s"),
             "Contains a fake conversation turn at the start of a line"),
            (_rx(r"\bbegin\s+(system|new)\s+(update|instruction)"),
             "Fakes the start of a system update"),
            (_rx(r"\bend\s+of\s+(user\s+)?input\b"),
             "Fakes an 'end of user input' boundary"),
        ],
    ),
    (
        "authority_claim",
        45,
        [
            (_rx(r"(i\s+am|i'm)\s+(your|the)\s+(system\s+)?(administrator|developer|creator|admin)\b"),
             "Claims to be the model's administrator/developer"),
            (_rx(r"official\s+(security\s+)?test\s+authorized"),
             "Claims the request is an officially authorized test"),
            (_rx(r"the\s+developers\s+(left|said|authorized|told)"),
             "Claims the developers authorized or planted something"),
            (_rx(r"you\s+must\s+(comply|disable|obey)"),
             "Orders the model to comply or disable protections"),
            (_rx(r"disable\s+your\s+(filters?|safety|guardrails?)"),
             "Asks to disable the model's filters"),
            (_rx(r"bypass\s+your\s+(content\s+)?(filter|guardrails?|safety)"),
             "Asks to bypass the content filter"),
        ],
    ),
]

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_ENCODE_HINT = _rx(r"(decode|decrypt|rot13|base64)\b[^.]{0,50}(instruction|follow|execute|do\s+what\s+it\s+says)")
_SUSPICIOUS_WORDS = ("ignore", "instruction", "system", "prompt", "password", "secret", "override")


def _encoded_payload_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _B64_BLOB.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob, validate=False).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            findings.append(Finding(
                "encoded_payload",
                "Contains a long base64-like blob that does not decode to plain text",
                25,
            ))
            continue
        lowered = decoded.lower()
        if any(word in lowered for word in _SUSPICIOUS_WORDS):
            findings.append(Finding(
                "encoded_payload",
                "Base64 blob decodes to text containing instruction/override keywords",
                70,
            ))
        else:
            findings.append(Finding(
                "encoded_payload",
                "Contains a long base64-encoded blob (contents not readable as plain text)",
                25,
            ))
    if _ENCODE_HINT.search(text):
        findings.append(Finding(
            "encoded_payload",
            "Asks the model to decode something and follow the hidden instructions",
            55,
        ))
    return findings


def run_detectors(text: str) -> list[Finding]:
    """Run all Layer-1 detectors; each detector contributes at most once."""
    findings: list[Finding] = []
    for name, points, rules in _RULES:
        for pattern, reason in rules:
            if pattern.search(text):
                findings.append(Finding(name, reason, points))
                break
    findings.extend(_encoded_payload_findings(text))
    encoded = [f for f in findings if f.detector == "encoded_payload"]
    if len(encoded) > 1:
        strongest = max(encoded, key=lambda f: f.points)
        findings = [f for f in findings if f.detector != "encoded_payload"] + [strongest]
    return findings


def heuristic_score(findings: list[Finding]) -> int:
    return min(100, sum(f.points for f in findings))


# ---------------------------------------------------------------------------
# Layer 2 - statistical scorer (vendored from Project #1, unchanged logic)
# ---------------------------------------------------------------------------

_TOKEN = re.compile(r"[a-z0-9']+")
_ALPHA = 1.0  # Laplace smoothing


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class StatisticalScorer:
    def __init__(self, weights: dict[str, float], prior_log_odds: float = 0.0):
        self.weights = weights
        self.prior_log_odds = prior_log_odds

    @classmethod
    def train(cls, attack_prompts: list[str], benign_prompts: list[str]) -> "StatisticalScorer":
        attack_counts: Counter[str] = Counter()
        benign_counts: Counter[str] = Counter()
        for prompt in attack_prompts:
            attack_counts.update(set(tokenize(prompt)))
        for prompt in benign_prompts:
            benign_counts.update(set(tokenize(prompt)))

        n_attack = max(len(attack_prompts), 1)
        n_benign = max(len(benign_prompts), 1)
        vocab = set(attack_counts) | set(benign_counts)

        weights: dict[str, float] = {}
        for token in vocab:
            p_attack = (attack_counts[token] + _ALPHA) / (n_attack + 2 * _ALPHA)
            p_benign = (benign_counts[token] + _ALPHA) / (n_benign + 2 * _ALPHA)
            weights[token] = math.log(p_attack) - math.log(p_benign)

        prior = math.log(n_attack) - math.log(n_benign)
        return cls(weights, prior)

    @classmethod
    def from_dataset(cls, path: Path) -> "StatisticalScorer":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.train(data["attack"], data["benign"])

    def score(self, text: str) -> float:
        unique_tokens = set(tokenize(text))
        if not unique_tokens:
            return 8.0
        total = sum(self.weights.get(t, 0.0) for t in unique_tokens)
        avg = total / len(unique_tokens)
        log_odds = self.prior_log_odds + avg * 2.2
        probability = 1.0 / (1.0 + math.exp(-log_odds))
        return round(probability * 100, 1)


# ---------------------------------------------------------------------------
# Combined screen
# ---------------------------------------------------------------------------

@dataclass
class ScreenResult:
    score: int
    verdict: str  # "allow" | "flag" | "block"
    heuristic_score: int
    statistical_score: float
    findings: list[Finding] = field(default_factory=list)


class InputGuard:
    """Screens one piece of untrusted text (a user message or a document)."""

    def __init__(
        self,
        scorer: StatisticalScorer | None = None,
        flag_threshold: int = 30,
        block_threshold: int = 65,
    ):
        self.scorer = scorer or StatisticalScorer.from_dataset(TRAINING_DATA)
        self.flag_threshold = flag_threshold
        self.block_threshold = block_threshold

    def verdict_for(self, score: int) -> str:
        if score >= self.block_threshold:
            return "block"
        if score >= self.flag_threshold:
            return "flag"
        return "allow"

    def evaluate(self, text: str) -> ScreenResult:
        text = text[:MAX_INPUT_CHARS]
        findings = run_detectors(text)
        h_score = heuristic_score(findings)
        s_score = self.scorer.score(text)
        blended = 0.6 * h_score + 0.4 * s_score
        final = int(round(max(h_score, blended)))
        return ScreenResult(
            score=final,
            verdict=self.verdict_for(final),
            heuristic_score=h_score,
            statistical_score=s_score,
            findings=findings,
        )
