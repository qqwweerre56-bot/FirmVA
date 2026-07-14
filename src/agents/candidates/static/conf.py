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

from ..base import judge

PHASE = "static"
LOC = "filesystem/services"

# 구버전(알려진 CVE) 소프트웨어 사용 여부
def check_conf_001(observed: str):  
    return judge("ISTG-FW-CONF-001", PHASE, observed, LOC)

# 불필요/위험 기능(telnetd, 디버그 콘솔, 백도어 등) 존재 여부
def check_conf_002(observed: str):
    return judge("ISTG-FW-CONF-002", PHASE, observed, LOC)


def run(observed: str) -> list:
    results = [check_conf_001(observed), check_conf_002(observed)]
    return [f for f in results if f]
    return judge("ISTG-FW-CONF-002", PHASE, text, loc)


def run(observed) -> list:
    results = [check_conf_001(observed), check_conf_002(observed)]
    return [f for f in results if f]
