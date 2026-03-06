"""Person name detector — requires context keywords to trigger."""

import re
from .base import BaseDetector, Match


class PersonNameDetector(BaseDetector):
    label = "PERSON_NAME"

    # Chinese name preceded by context keywords (2-4 chars)
    BEFORE_NAME = re.compile(
        r'(?:姓名|名字|收件人|联系人|持卡人|户名|开户人|患者|被告|原告|当事人)'
        r'[：:\s]*'
        r'([\u4e00-\u9fff]{2,4})',
    )

    # Chinese name followed by honorific title
    AFTER_TITLE = re.compile(
        r'([\u4e00-\u9fff]{2,4})'
        r'(?:先生|女士|同志|老师|教授|医生|律师)',
    )

    # Structured: Name/姓名: value (Chinese or English)
    STRUCTURED = re.compile(
        r'(?:name|姓名|收件人|联系人|持卡人|户名)'
        r'[\s：:=]*'
        r'([A-Z][a-z]+ [A-Z][a-z]+|[\u4e00-\u9fff]{2,4})',
        re.IGNORECASE
    )

    def detect(self, text):
        matches = []
        seen = set()

        for pattern in [self.BEFORE_NAME, self.AFTER_TITLE, self.STRUCTURED]:
            for m in pattern.finditer(text):
                name = m.group(1)
                if name in seen:
                    continue
                seen.add(name)
                masked = name[0] + '*' * (len(name) - 1)
                matches.append(Match(
                    label=self.label,
                    confidence=0.70,
                    masked_preview=masked,
                    start=m.start(1),
                    end=m.end(1),
                ))
        return matches
