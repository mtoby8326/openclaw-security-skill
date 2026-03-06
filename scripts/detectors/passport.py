"""Passport number detector — context-keyword gated to reduce false positives."""

import re
from .base import BaseDetector, Match


class PassportDetector(BaseDetector):
    label = "PASSPORT"

    # Chinese passport: E/G/D/S/P/H + optional letter + 7-8 digits
    CN_PASSPORT = re.compile(r'(?<![A-Za-z])([EGDSPHegdsph][A-Za-z]?\d{7,8})(?!\d)')

    # Context keywords that must be present to trigger detection
    CONTEXT_KW = re.compile(
        r'护照|passport|travel\s*document|签证|visa|出入境',
        re.IGNORECASE
    )

    def detect(self, text):
        if not self.CONTEXT_KW.search(text):
            return []  # No context — skip entirely to avoid false positives

        matches = []
        for m in self.CN_PASSPORT.finditer(text):
            raw = m.group()
            digits = re.sub(r'[^0-9]', '', raw)
            if len(digits) < 7:
                continue
            matches.append(Match(
                label=self.label,
                confidence=0.85,
                masked_preview=raw[:2] + '****' + raw[-2:],
                start=m.start(),
                end=m.end(),
            ))
        return matches
