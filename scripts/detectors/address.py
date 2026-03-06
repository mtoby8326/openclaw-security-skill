"""Chinese address detector — keyword-gated and structural province/city patterns."""

import re
from .base import BaseDetector, Match


class AddressDetector(BaseDetector):
    label = "ADDRESS"

    # After context keyword
    KEYWORD_ADDR = re.compile(
        r'(?:地址|住址|收货地址|寄送地址|通讯地址|address)'
        r'[：:\s]*'
        r'([\u4e00-\u9fff\w\d\-\u2014#\u53f7\u697c\u680b\u5355\u5143\u5ba4\u5c42\u5e62\u5f04\u5df7\u8def\u8857\u9053\u533a\u53bf\u5e02\u7701]{8,60})',
        re.IGNORECASE
    )

    # Province + City + details
    PROVINCIAL = re.compile(
        r'([\u4e00-\u9fff]{2,6}(?:\u7701|\u81ea\u6cbb\u533a)'
        r'[\u4e00-\u9fff]{2,10}(?:\u5e02|\u5dde|\u76df)'
        r'[\u4e00-\u9fff\w\d\-\u2014#\u53f7\u697c\u680b\u5355\u5143\u5ba4\u5c42\u5e62\u5f04\u5df7\u8def\u8857\u9053\u533a\u53bf]{4,40})',
    )

    # Direct-controlled municipalities: Beijing, Shanghai, Tianjin, Chongqing
    MUNICIPAL = re.compile(
        r'((?:\u5317\u4eac|\u4e0a\u6d77|\u5929\u6d25|\u91cd\u5e86)\u5e02?'
        r'[\u4e00-\u9fff]{2,6}(?:\u533a|\u53bf)'
        r'[\u4e00-\u9fff\w\d\-\u2014#\u53f7\u697c\u680b\u5355\u5143\u5ba4\u5c42\u5e62\u5f04\u5df7\u8def\u8857\u9053]{4,30})',
    )

    def detect(self, text):
        matches = []
        seen = set()

        for pattern in [self.KEYWORD_ADDR, self.PROVINCIAL, self.MUNICIPAL]:
            for m in pattern.finditer(text):
                addr = m.group(1)
                if addr in seen or len(addr) < 8:
                    continue
                seen.add(addr)
                if len(addr) > 6:
                    masked = addr[:4] + '****' + addr[-2:]
                else:
                    masked = '****'
                matches.append(Match(
                    label=self.label,
                    confidence=0.75,
                    masked_preview=masked,
                    start=m.start(1),
                    end=m.end(1),
                ))
        return matches
