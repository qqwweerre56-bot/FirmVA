# candidates/static/conf.py: 소프트웨어 구성(Configuration/Composition) 계열 (한 파일 통합)
########################################################
# ISTG-FW-CONF-001  Usage of Outdated Software
# ISTG-FW-CONF-002  Presence of Unnecessary Software and Functionalities

# 통합 이유:
# 두 항목 모두 '설치된 구성요소/서비스 목록과 버전 문자열'이라는
# 같은 관찰 데이터를 근거로 판정합니다.

# 입력 : observed (StaticRaw JSON)
# 출력 : 취약 판정 Finding 목록
########################################################

import json
import re
from ..base import judge

PHASE = "static"

VERSION_LIKE_PATTERN = re.compile(
    r"([A-Za-z][A-Za-z0-9_\-]{2,20})[\s/_-]v?(\d+\.\d+(?:\.\d+)?[a-z]?)"
)


GENERIC_RISKY_SERVICE_HINTS = [
    "telnet", "ftp", "debug", "test", "shell", "backdoor", "support",
]


def _to_raw(observed):
    if hasattr(observed, "model_dump"):
        return observed.model_dump()
    return json.loads(observed)


def _extract_version_strings(raw: dict):
    """벤더 무관: '이름+버전' 패턴에 매치되는 모든 문자열을 위치정보와 함께 수집"""
    found = []

    services_text = " ".join(raw.get("services", []))
    for m in VERSION_LIKE_PATTERN.finditer(services_text):
        found.append({"location": "services", "text": m.group(0)})

    for b in raw.get("binaries", []):
        text = "\n".join(b.get("strings", []))
        for m in VERSION_LIKE_PATTERN.finditer(text):
            found.append({"location": b["path"], "text": m.group(0)})

    return found


def _extract_risky_service_hints(raw: dict):
    """벤더 무관: 이름에 관리/디버그성 키워드가 들어간 서비스/파일/설정만 후보로"""
    candidates = []

    for s in raw.get("services", []):
        if any(k in s.lower() for k in GENERIC_RISKY_SERVICE_HINTS):
            candidates.append({"location": "services", "text": s})

    for f in raw.get("files", []):
        if any(k in f.lower() for k in GENERIC_RISKY_SERVICE_HINTS):
            candidates.append({"location": f, "text": f})

    for cfg in raw.get("configs", []):
        if any(k in cfg.lower() for k in GENERIC_RISKY_SERVICE_HINTS):
            candidates.append({"location": f"config: {cfg[:40]}...", "text": cfg})

    return candidates


def check_conf_001(observed):
    raw = _to_raw(observed)
    versions = _extract_version_strings(raw)
    if not versions:
        return None  
    loc = ", ".join(sorted({v["location"] for v in versions}))
    text = json.dumps(versions, ensure_ascii=False)
    return judge("ISTG-FW-CONF-001", PHASE, text, loc)


def check_conf_002(observed):
    raw = _to_raw(observed)
    candidates = _extract_risky_service_hints(raw)
    if not candidates:
        return None
    loc = ", ".join(sorted({c["location"] for c in candidates}))
    text = json.dumps(candidates, ensure_ascii=False)
    return judge("ISTG-FW-CONF-002", PHASE, text, loc)


def run(observed) -> list:
    results = [check_conf_001(observed), check_conf_002(observed)]
    return [f for f in results if f]
