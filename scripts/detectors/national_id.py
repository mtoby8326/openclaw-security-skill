"""Chinese national ID card (身份证) detector with checksum validation."""

import re
from .base import BaseDetector, Match


class NationalIdDetector(BaseDetector):
    label = "NATIONAL_ID"

    # 18-digit: 6 region + 8 birthday (19xx/20xx) + 3 seq + 1 check (digit or X)
    PATTERN = re.compile(
        r'(?<!\d)'
        r'(\d{6})'                          # region code
        r'((?:19|20)\d{2})'                 # birth year
        r'((?:0[1-9]|1[0-2]))'             # birth month
        r'((?:0[1-9]|[12]\d|3[01]))'       # birth day
        r'(\d{3})'                          # sequence
        r'(\d|X|x)'                         # check digit
        r'(?!\d)'
    )

    WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    CHECK_CODES = '10X98765432'

    def _verify_checksum(self, id_str):
        """Verify the 18-digit ID checksum."""
        digits = id_str[:17]
        if not digits.isdigit():
            return False
        total = sum(int(d) * w for d, w in zip(digits, self.WEIGHTS))
        expected = self.CHECK_CODES[total % 11]
        return id_str[17].upper() == expected

    def detect(self, text):
        matches = []
        for m in self.PATTERN.finditer(text):
            raw = m.group()
            if not self._verify_checksum(raw):
                continue  # Checksum fail — skip to reduce false positives
            matches.append(Match(
                label=self.label,
                confidence=0.98,
                masked_preview=raw[:6] + '********' + raw[-4:],
                start=m.start(),
                end=m.end(),
            ))
        return matches
