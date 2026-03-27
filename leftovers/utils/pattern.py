"""Pattern compilation and token matching utilities."""

import re
from typing import Dict, List, Optional, Set, Tuple

from leftovers.utils.text import rot13

# Type aliases to reduce line length
PatternList = List[Tuple[str, re.Pattern[str], float]]
PatternDict = Dict[str, PatternList]


def compile_term_patterns(
    terms: List[str],
    mode_filter: Optional[Set[str]] = None,
) -> Dict[str, List[Tuple[str, re.Pattern[str], float]]]:
    active_modes = mode_filter or {"exact", "substring", "segment", "rot13"}
    patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]] = {
        "exact": [],
        "substring": [],
        "segment": [],
        "rot13": [],
    }
    seen: Set[Tuple[str, str]] = set()
    for term in terms:
        clean = (term or "").strip()
        if len(clean) < 2:
            continue
        norm = clean.lower()

        key = (norm, "exact")
        if key not in seen and "exact" in active_modes:
            seen.add(key)
            patterns["exact"].append((norm, re.compile(rf"\b{re.escape(clean)}\b", re.IGNORECASE), 1.0))

        key = (norm, "substring")
        if key not in seen and "substring" in active_modes:
            seen.add(key)
            patterns["substring"].append((norm, re.compile(re.escape(clean), re.IGNORECASE), 0.6))

        key = (norm, "segment")
        if key not in seen and "segment" in active_modes:
            seen.add(key)
            patterns["segment"].append(
                (
                    norm,
                    re.compile(rf"(?:^|[\\/\.\-_]){re.escape(clean)}(?:$|[\\/\.\-_])", re.IGNORECASE),
                    0.4,
                )
            )

        if "rot13" in active_modes:
            rot = rot13(clean)
            key = (rot.lower(), "rot13")
            if key not in seen:
                seen.add(key)
                patterns["rot13"].append((norm, re.compile(re.escape(rot), re.IGNORECASE), 0.8))
    return patterns


def merge_term_patterns(
    base: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    extra: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
) -> Dict[str, List[Tuple[str, re.Pattern[str], float]]]:
    merged: Dict[str, List[Tuple[str, re.Pattern[str], float]]] = {
        "exact": list(base.get("exact", [])),
        "substring": list(base.get("substring", [])),
        "segment": list(base.get("segment", [])),
        "rot13": list(base.get("rot13", [])),
    }
    seen = {
        mode: {(term, pattern.pattern, weight) for term, pattern, weight in merged.get(mode, [])}
        for mode in merged
    }
    for mode, items in extra.items():
        for term, pattern, weight in items:
            sig = (term, pattern.pattern, weight)
            if sig in seen[mode]:
                continue
            seen[mode].add(sig)
            merged[mode].append((term, pattern, weight))
    return merged


def token_hits(text: str, patterns: PatternDict, allow_rot13: bool = False) -> List[Tuple[str, str, float]]:
    sample = text or ""
    hits: List[Tuple[str, str, float]] = []
    for mode in ["exact", "substring", "segment"]:
        for term, pattern, weight in patterns.get(mode, []):
            if pattern.search(sample):
                hits.append((term, mode, weight))
    if allow_rot13:
        for term, pattern, weight in patterns.get("rot13", []):
            if pattern.search(sample):
                hits.append((term, "rot13", weight))
    return hits


def token_hit_terms(text: str, patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]], allow_rot13: bool = False) -> List[str]:
    terms: List[str] = []
    seen: Set[str] = set()
    for term, _, _ in token_hits(text, patterns, allow_rot13=allow_rot13):
        if term in seen:
            continue
        seen.add(term)
        terms.append(term)
    return terms


def token_hit_weight(text: str, patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]], allow_rot13: bool = False) -> float:
    hits = token_hits(text, patterns, allow_rot13=allow_rot13)
    if not hits:
        return 0.0
    return max(weight for _, _, weight in hits)
