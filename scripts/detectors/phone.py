"""Phone number detector - Chinese mobile, landline, and international formats."""

import re
from .base import BaseDetector, Match


class PhoneDetector(BaseDetector):
    label = "PHONE"

    # Chinese mobile: 1[3-9]X XXXX XXXX (optional separators)
    CN_MOBILE = re.compile(r'(?<!\d)1[3-9]\d[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)')
    # International: +CC XXXXXXXX (country code + 4-14 digits)
    INTL = re.compile(r'\+\d{1,3}[\s\-]?\d{4,14}(?!\d)')
    # Chinese landline: 0XX(X)-XXXXXXX(X)
    CN_LANDLINE = re.compile(r'(?<!\d)0\d{2,3}[\s\-]?\d{7,8}(?!\d)')

    def detect(self, text):
        matches = []
        seen_positions = set()

        for pattern in [self.CN_MOBILE, self.INTL, self.CN_LANDLINE]:
            for m in pattern.finditer(text):
                if m.start() in seen_positions:
                    continue
                raw = m.group()
                clean = re.sub(r'[\s\-]', '', raw)
                digits = re.sub(r'\D', '', clean)
                if len(digits) < 7 or len(digits) > 15:
                    continue
                seen_positions.add(m.start())
                matches.append(Match(
                    label=self.label,
                    confidence=0.90,
                    masked_preview=self._mask(clean),
                    start=m.start(),
                    end=m.end(),
                ))
        return matches
