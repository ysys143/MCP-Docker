# MCP 서버 도커 실행 및 클라이언트 설정 가이드

## 프로젝트 구조

```
mcp-docker/
├── oauth2-demo/                    # 🔐 OAuth2 + 보안 데모 서버
│   ├── core/                       #   핵심 OAuth2 모듈
│   │   ├── mcp_oauth2_server.py   #     통합 OAuth2 FastAPI 서버
│   │   ├── oauth2_web_server.py   #     분리형 OAuth2 웹 서버
│   │   ├── oauth2_mcp_tools.py    #     OAuth2 MCP 도구들
│   │   └── oauth2_common.py       #     JWT 토큰 & 인증 공통 로직
│   ├── security/                   #   보안 기능 모듈
│   │   ├── security_common.py     #     PII 탐지, 암호화, 감사 로깅
│   │   ├── secure_mcp_tools.py    #     보안 적용된 MCP 도구들
│   │   └── pii_patterns.json      #     PII 패턴 정의
│   ├── tests/                      #   포괄적 테스트 스위트
│   │   ├── test_oauth2_demo.py    #     OAuth2 플로우 테스트
│   │   ├── test_mcp_tools_direct.py #   MCP 도구 직접 테스트
│   │   ├── test_mcp_integration.py #    MCP 통합 테스트
│   │   ├── test_security_integration.py # 보안 통합 테스트
│   │   ├── keys/                  #     테스트용 암호화 키
│   │   └── logs/                  #     테스트 감사 로그
│   ├── config/                     #   설정 파일들
│   │   └── Dockerfile             #     OAuth2 서버용 Docker 파일
│   ├── docs/                       #   OAuth2 상세 문서
│   │   ├── README.md              #     완전한 OAuth2 가이드
│   │   └── README_SEPARATED.md    #     분리형 구조 설명
│   ├── keys/                       #   JWT 암호화 키 저장소
│   ├── logs/                       #   보안 감사 로그
│   │   └── security_audit.log     #     실시간 보안 이벤트 로그
│   ├── README.md                   #   OAuth2 데모 메인 문서
│   └── __init__.py                 #   Python 패키지 초기화
├── docker/                         # Docker 관련 파일들
│   └── dockerfile                  #   메인 Python MCP 서버용 Docker 파일
├── scripts/                        # 실행 스크립트들
│   └── run_mcp_server_with_logging.sh # MCP 서버 로깅 스크립트
├── examples/                       # 예제 파일들
│   └── custom_mcp_server.py        #   기본 MCP 서버 예제
├── .cursor/                        # Cursor IDE 설정
│   └── mcp.json                    #   MCP 클라이언트 설정
├── .venv/                          # Python 가상환경 (uv)
├── docker-compose.yml              # 🐳 Docker Compose 통합 설정
│                                   #   - mcp-python-server-docker (포트 8080)
│                                   #   - mcp-oauth2-web-server (포트 8081)
│                                   #   - mcp-node-server-docker
├── requirements.txt                # Python 의존성 패키지
├── QUICK_START.md                  # 빠른 시작 가이드
├── README_KOR.md                   # 📖 한국어 메인 문서 (이 파일)
└── README.md                       # 📖 영어 메인 문서
```

![How Docker Revolutionizes MCP](charts/docker-mcp.png)
[Docker Blog: How to build and deliver an MCP server for production](https://www.docker.com/blog/build-to-prod-mcp-servers-with-docker/)


### 🏗️ 아키텍처 구성

#### 전체 시스템 아키텍처

![시스템 아키텍처](charts/system-architecture.png)

#### 1️⃣ **메인 MCP 서버 스택**
- **Python MCP 서버**: 포트 8080에서 실행되는 메인 MCP 도구들
- **Node.js MCP 서버**: Context7, sequential-thinking 등 Node.js 기반 도구들
- **Docker 격리**: 각 서버는 독립적인 컨테이너에서 안전하게 실행

#### 2️⃣ **OAuth2 + 보안 스택**
- **OAuth2 Authorization Server**: JWT 토큰 발급 (client_credentials 플로우)
- **OAuth2 Resource Server**: 보호된 MCP 엔드포인트 제공
- **PII 탐지 & 마스킹**: 개인식별정보 자동 식별 및 보호
- **데이터 암호화**: Fernet 알고리즘 기반 민감 데이터 보호
- **보안 감사 로깅**: 모든 보안 이벤트 실시간 추적

#### 3️⃣ **통합 테스트 시스템**
- **OAuth2 플로우 테스트**: 토큰 발급, 인증, 보호된 리소스 접근
- **MCP 도구 테스트**: 직접 호출 및 통합 시나리오 테스트
- **보안 통합 테스트**: PII 탐지, 암호화, 감사 로깅 검증
- **자동화된 CI/CD**: 모든 기능의 지속적 검증

#### Docker 네트워크 구성

![Docker 네트워크](charts/system-architecture.png)

## 🔐 OAuth2 및 보안 인증 작동방식

### OAuth2 Client Credentials 플로우

본 프로젝트는 **OAuth2 Client Credentials Grant** 방식을 사용하여 서버 간 인증을 구현합니다.

#### 1️⃣ **인증 플로우 단계**

OAuth2 Client Credentials 플로우는 다음과 같이 진행됩니다:

1. **토큰 요청**: MCP 클라이언트가 OAuth2 서버에 `client_credentials` 방식으로 토큰 요청
2. **클라이언트 인증**: 서버가 client_id/client_secret 검증
3. **JWT 토큰 발급**: 검증 성공 시 JWT 액세스 토큰 발급
4. **보호된 리소스 요청**: Bearer 토큰으로 MCP 리소스 서버에 요청
5. **토큰 검증**: 리소스 서버가 JWT 서명 및 유효성 검증
6. **리소스 응답**: 검증 성공 시 MCP 도구 실행 결과 반환

#### 2️⃣ **세부 구현 방식**

##### **토큰 발급 과정**
```bash
# 1단계: 클라이언트 인증 및 토큰 요청
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"

# 응답: JWT 토큰
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "mcp.access"
}
```

##### **JWT 토큰 구조**
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "mcp-client",           // 클라이언트 ID
    "aud": "mcp-client",           // 대상 서비스
    "scope": "mcp.access",         // 권한 범위
    "exp": 1704533400,             // 만료 시간
    "iat": 1704531600,             // 발급 시간
    "jti": "unique-token-id"       // 토큰 고유 ID
  },
  "signature": "HMACSHA256(...)"   // 서명
}
```

##### **토큰 검증 과정**
```python
# FastAPI에서 자동 토큰 검증
@app.get("/protected-endpoint")
async def protected_resource(current_client: str = Depends(get_current_client)):
    # 1. Authorization 헤더에서 Bearer 토큰 추출
    # 2. JWT 서명 검증 (SECRET_KEY 사용)
    # 3. 토큰 만료 시간 확인
    # 4. scope에 'mcp.access' 포함 여부 확인
    # 5. 검증 성공 시 클라이언트 ID 반환
    return {"message": f"인증된 클라이언트: {current_client}"}
```

### 🛡️ 다층 보안 아키텍처

#### 보안 처리 플로우

![보안 처리 플로우](charts/security-flow.png)

#### 보안 레이어 구조

![보안 처리 플로우](charts/security-flow.png)

#### 1️⃣ **PII (개인식별정보) 탐지 시스템**

```python
# PII 패턴 정의 (pii_patterns.json)
{
  "email": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
  "phone": "\\b01[0-9]-?[0-9]{4}-?[0-9]{4}\\b",
  "korean_name": "\\b[가-힣]{2,4}\\b(?=님|씨|\\s|$)",
  "ssn": "\\b\\d{6}-?[1-4]\\d{6}\\b"
}

# 실시간 PII 탐지 및 처리
def scan_and_process_pii(text: str, policy: str = "encrypt"):
    detected_pii = pii_detector.scan_text(text)
    
    if detected_pii:
        if policy == "encrypt":
            return encryption_service.encrypt(text)
        elif policy == "mask":
            return pii_detector.mask_pii(text)
        elif policy == "reject":
            raise SecurityException("PII 포함으로 요청 거부")
    
    return text
```

#### 2️⃣ **데이터 암호화 시스템**

```python
# Fernet 대칭 암호화 사용
from cryptography.fernet import Fernet

class EncryptionService:
    def __init__(self):
        self.fernet = Fernet(self._load_or_generate_key())
    
    def encrypt(self, data: str) -> str:
        """민감한 데이터를 암호화"""
        encrypted = self.fernet.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """암호화된 데이터를 복호화"""
        decoded = base64.b64decode(encrypted_data.encode())
        decrypted = self.fernet.decrypt(decoded)
        return decrypted.decode()
```

#### 3️⃣ **보안 감사 로깅**

```python
# 모든 보안 이벤트 실시간 기록
def log_security_event(event_type: str, tool_name: str, 
                      user_id: str, client_id: str, 
                      contains_pii: bool, action_taken: str):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "tool_name": tool_name,
        "user_id": user_id,
        "client_id": client_id,
        "contains_pii": contains_pii,
        "action_taken": action_taken,
        "parameter_count": len(params)
    }
    
    # JSON 형태로 보안 감사 로그에 기록
    security_logger.info(json.dumps(log_entry, ensure_ascii=False))
```

#### 4️⃣ **통합 보안 데코레이터**

```python
@secure_tool(requires_encryption=True, log_access=True, pii_policy="encrypt")
async def process_customer_data(customer_info: str, client_id: str, user_id: str):
    """
    보안 데코레이터가 자동으로:
    1. PII 탐지 수행
    2. 정책에 따라 암호화/마스킹/거부 처리
    3. 모든 접근을 감사 로그에 기록
    4. 암호화가 필요한 경우 자동 암호화
    """
    # 실제 비즈니스 로직 실행
    return {"status": "processed", "data": customer_info}
```

### 🔄 실제 인증 흐름 예제

#### MCP 도구 호출 플로우

![MCP 실행 플로우](charts/mcp-execution-flow.png)

#### 데이터 처리 흐름

![MCP 실행 플로우](charts/mcp-execution-flow.png)

#### **Cursor에서 MCP 도구 호출 시**

```bash
# 1. Cursor가 Docker 컨테이너 내 MCP 도구 호출
docker exec -i mcp-python-server-docker uv run /workspace/oauth2-demo/core/oauth2_mcp_tools.py

# 2. MCP 도구가 OAuth2 서버에 토큰 요청
POST http://localhost:8081/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access

# 3. OAuth2 서버가 JWT 토큰 발급
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800
}

# 4. MCP 도구가 보호된 리소스에 토큰으로 접근
GET http://localhost:8081/hello
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 5. 서버가 토큰 검증 후 응답
{
  "message": "MCP OAuth2 데모에서 안녕하세요!",
  "authenticated_client": "mcp-client",
  "timestamp": "2025-01-06T12:34:56"
}
```

#### **보안 기능 작동 시**

```python
# 민감한 데이터 처리 요청
input_data = "고객 정보: 홍길동님 (hong@example.com, 010-1234-5678)"

# 1. PII 자동 탐지
detected_pii = [
    {"type": "korean_name", "value": "홍길동", "start": 6, "end": 9},
    {"type": "email", "value": "hong@example.com", "start": 13, "end": 30},
    {"type": "phone", "value": "010-1234-5678", "start": 32, "end": 45}
]

# 2. 보안 정책 적용 (encrypt)
encrypted_data = "gAAAAABhK3x2y8X9..."

# 3. 감사 로그 기록
{
  "timestamp": "2025-01-06T12:34:56",
  "event_type": "tool_access",
  "tool_name": "process_customer_data",
  "user_id": "cursor_user",
  "client_id": "mcp-client",
  "contains_pii": true,
  "action_taken": "executed_with_encryption"
}
```

### 🔒 보안 정책 선택

| 정책 | 설명 | 사용 시나리오 |
|------|------|---------------|
| `encrypt` | PII 발견 시 자동 암호화 후 처리 | 민감한 데이터 저장/전송 |
| `mask` | PII를 마스킹(****) 처리 후 진행 | 로그, 디버깅, 프리뷰 |
| `reject` | PII 발견 시 요청 즉시 거부 | 고보안 환경, 규정 준수 |

#### 테스트 아키텍처

![시스템 아키텍처](charts/system-architecture.png)

#### Docker 배포 과정

![시스템 아키텍처](charts/system-architecture.png)

이러한 다층 보안 아키텍처를 통해 **OAuth2 인증** + **PII 보호** + **데이터 암호화** + **감사 추적**의 완전한 보안 솔루션을 제공합니다.

![How Docker Revolutionizes MCP](docs/docker-mcp.png)
[Docker Blog: How to build and deliver an MCP server for production](https://www.docker.com/blog/build-to-prod-mcp-servers-with-docker/)

기존 MCP(Model Context Protocol) 워크플로우의 문제점

*   **복잡한 관리**: 각 MCP 클라이언트는 모든 MCP 서버의 자체 복사본을 항상 실행해야 했으며, 이는 로컬 리소스를 과도하게 소모했습니다. 클라이언트마다 서버 세트를 직접 구성해야 했고, 어떤 MCP 서버를 사용해야 하는지 파악하기 어려웠으며, 일부 MCP 서버는 특정 에이전트에서 작동하지 않는 호환성 문제도 있었습니다.
*   **의존성 지옥**: MCP 서버는 모든 런타임 및 의존성이 설치되어 있어야만 작동. 에이전트는 호스트 리소스에 직접 접근 권한을 가지고 있어 보안에 취약.
*   **보안 문제**: API 키를 평문 설정 파일에 수동으로 구성해야 했고, 인증 서버 관리도 번거로움.

Docker를 통해 MCP 서버 실행환경을 격리하면,

*   **단순화된 런타임**: Docker를 사용하면 하나의 런타임 애플리케이션으로 MCP 도구 설치를 표준화.
*   **격리 및 보안**: Docker 컨테이너는 에이전트를 샌드박스 처리하여 호스트 리소스에 대한 불필요한 접근을 방지하는 데 효과적. 또한, API 키를 평문 설정 파일에 저장하지 않고 안전하게 관리하고, OAuth를 통한 서버 인증을 고려할 수 있어 보안 강화 가능.
*   **쉬운 접근성**: 클라이언트는 단일 엔드포인트를 통해 MCP 서비스에 접근할 수 있으며, 이로 인해 사용자가 명시적으로 설치하지 않은 도구라도 에이전트가 작업에 적합한 도구를 사용할 수 있는 유연성 확보 가능.


# 설정방법


## 1. 전제 조건

-   Docker가 설치되어 있어야 합니다. [Docker 공식 웹사이트](https://www.docker.com/get-started)에서 설치할 수 있습니다.


## 2. Docker 컨테이너 실행

node20 이미지를 도커로 띄웁니다. 

```bash
docker run -d --name mcp-node-server-docker -it node:20-slim bash
```

> **참고**: `--name` 옵션으로 지정된 컨테이너 이름(`mcp-node-server-docker`)은 Docker 호스트 내에서 고유해야 합니다. 같은 이름의 컨테이너가 이미 실행 중이거나 중지된 상태라면 새 컨테이너를 시작할 수 없습니다. 이 경우 기존 컨테이너를 중지 및 제거하거나 다른 이름을 사용해야 합니다.


## 3. MCP 클라이언트 설정 (.cursor/mcp.json 예시)

MCP 클라이언트(예: Cursor)는 `mcp.json` 파일을 통해 Context7 Documentation MCP 서버에 연결하는 방법을 설정합니다. 이 파일은 일반적으로 클라이언트의 설정 디렉토리(`~/.cursor/mcp.json` 등)에 위치하며, **Docker 컨테이너 내부로 복사되지 않습니다.**

이 설정 방식은 `docker exec`를 사용하여 컨테이너 내부에서 직접 MCP 서버 스크립트를 호출하므로, 별도의 포트 매핑(`-p` 옵션)이 필요 없습니다.

**컨테이너 내부 명령어 실행 확인 (선택 사항):**
MCP 서버가 컨테이너 내에서 제대로 구동 준비가 되었는지 확인하려면, 다음 명령으로 컨테이너 내부에 접속하여 MCP 서버 스크립트를 직접 실행해볼 수 있습니다:

```bash
docker exec -it mcp-node-server-docker bash
# (컨테이너 내부에서) npx -y @upstash/context7-mcp@latest
# 또는 Python 기반 서버의 경우:
# docker exec -it mcp-python-server-docker bash
# (컨테이너 내부에서) uv run /app/custom_mcp_server.py
```

`mcp.json` 파일을 다음과 같이 설정하여 Docker 컨테이너 내에서 실행 중인 Context7 MCP 서버에 연결할 수 있습니다:

```json
{
    "mcpServers": {
        "Context7 MCP (Docker exec)": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-node-server-docker",
                "npx",
                "-y",
                "@upstash/context7-mcp@latest"
            ]
        },
        "sequential-thinking (Docker exec)": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-node-server-docker",
                "npx",
                "-y",
                "@modelcontextprotocol/server-sequential-thinking"
            ]
        }
    }
}
```


## 4. 컨테이너 중지 및 제거 (선택 사항)

컨테이너를 중지하고 제거하려면 다음 명령을 사용합니다.

```bash
docker stop mcp-node-server-docker
docker rm mcp-node-server-docker
```

이 가이드에 따라 Context7 Documentation MCP 서버를 Docker 환경에서 쉽게 배포하고 클라이언트에서 설정하여 활용할 수 있습니다.



------------------


## 5. 커스텀 빌드 하는 경우

### 5.1. Node.js 기반 MCP 서버 커스텀 빌드

Context7 Documentation MCP 서버는 Node.js 기반입니다. 다음 `Dockerfile`을 사용하여 Node.js 환경에서 서버를 빌드하고 실행할 수 있습니다.

```dockerfile
FROM node:20-slim
WORKDIR /app
CMD ["tail", "-f", "/dev/null"]
```

`Dockerfile`이 있는 프로젝트 루트 디렉토리에서 다음 명령을 실행하여 Docker 이미지를 빌드합니다.
빌드된 이미지에 `node-base-image`와 같은 일반적인 이름을 태그합니다.

```bash
docker build -t node-base-image .
```

빌드된 이미지를 사용하여 Docker 컨테이너를 실행합니다.

```bash
docker run -d --name mcp-node-server-docker -it node-base-image
```

-   `-d`: 컨테이너를 백그라운드에서 실행합니다.
-   `--name mcp-node-server-docker`: 컨테이너에 `mcp-node-server-docker`라는 이름을 지정합니다.
    > **참고**: `--name` 옵션으로 지정된 컨테이너 이름(`mcp-node-server-docker`)은 Docker 호스트 내에서 고유해야 합니다. 같은 이름의 컨테이너가 이미 실행 중이거나 중지된 상태라면 새 컨테이너를 시작할 수 없습니다. 이 경우 기존 컨테이너를 중지 및 제거하거나 다른 이름을 사용해야 합니다.
-   `-it`: 컨테이너의 상호 작용 모드를 활성화하고 TTY를 할당합니다. 이는 컨테이너 내부에서 명령을 실행할 때 유용합니다.
-   `node-base-image`: 실행할 Docker 이미지의 이름입니다.

### 5.2. Python (`uv`) 기반 MCP 서버 커스텀 빌드 (예시)

만약 Python 기반 MCP 서버를 사용하고 `uv`로 의존성을 관리한다면, 다음과 유사한 `Dockerfile`을 구성할 수 있습니다. 이 예시는 `requirements.txt` 파일이 프로젝트 루트에 존재한다고 가정합니다.

```dockerfile
FROM python:3.10-slim-buster
WORKDIR /app

# 필요한 시스템 패키지 설치 및 캐시 정리
RUN apt-get update && apt-get install -y --no-install-recommends curl tar \
    && rm -rf /var/lib/apt/lists/*

# uv 설치 (권장)
# 최신 uv 바이너리를 다운로드하여 /usr/local/bin에 설치합니다.
RUN curl -sSfL https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv

# 의존성 설치
COPY requirements.txt .
RUN uv pip install -r requirements.txt --system

# MCP 서버 스크립트 복사 및 빌드 (필요한 경우)
# 예시: custom_mcp_server.py라는 파일이 있다고 가정
COPY custom_mcp_server.py .
# custom_mcp_server.py는 표준 입력(stdin)과 표준 출력(stdout)을 통해 JSON-RPC 요청/응답을 처리하는 MCP 서버여야 합니다.

CMD ["tail", "-f", "/dev/null"]
```

`Dockerfile`이 있는 프로젝트 루트 디렉토리에서 다음 명령을 실행하여 Docker 이미지를 빌드합니다.
빌드된 이미지에 `python-mcp-base-image`와 같은 일반적인 이름을 태그합니다.

```bash
docker build -t python-mcp-base-image .
```

빌드된 이미지를 사용하여 Docker 컨테이너를 실행합니다.

```bash
docker run -d --name mcp-python-server-docker -it python-mcp-base-image
```

-   `-d`: 컨테이너를 백그라운드에서 실행합니다.
-   `--name mcp-python-server-docker`: 컨테이너에 `mcp-python-server-docker`라는 이름을 지정합니다.
-   `-it`: 컨테이너의 상호 작용 모드를 활성화하고 TTY를 할당합니다.
-   `python-mcp-base-image`: 실행할 Docker 이미지의 이름입니다.

컨테이너 내에서 Python 기반 MCP 서버를 실행하는 `mcp.json` 클라이언트 설정 예시는 다음과 같습니다:

```json
{
    "mcpServers": {
        "Python Weather MCP (Docker exec)": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-python-server-docker",
                "uv",
                "run",
                "/app/custom_mcp_server.py"
            ]
        }
    }
}
```
이 설정을 추가한 후에는 MCP 클라이언트(예: Cursor)를 재시작하여 변경 사항을 적용해야 합니다.

컨테이너를 중지하고 제거하려면 다음 명령을 사용합니다.

```bash
docker stop mcp-python-server-docker
docker rm mcp-python-server-docker
```


------------------


## 6. OAuth2 + 보안 데모 사용법

### 6.1. Docker Compose로 전체 스택 실행

```bash
# 전체 스택 실행 (Python + Node.js + OAuth2 서버)
docker-compose up -d

# 특정 서비스만 실행
docker-compose up -d mcp-server oauth2-web-server

# 서비스 상태 확인
docker-compose ps
```

### 6.2. OAuth2 서버 테스트

```bash
# OAuth2 서버 상태 확인
curl http://localhost:8081/.well-known/openid-configuration

# 토큰 획득
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"

# 보호된 엔드포인트 접근
curl -H "Authorization: Bearer <토큰>" http://localhost:8081/hello
```

### 6.3. 보안 기능 테스트

```bash
# 가상환경 활성화
source .venv/bin/activate

# OAuth2 플로우 자동 테스트
python oauth2-demo/tests/test_oauth2_demo.py

# MCP 도구 직접 테스트
python oauth2-demo/tests/test_mcp_tools_direct.py

# 보안 통합 테스트
python oauth2-demo/tests/test_mcp_integration.py
```

### 6.4. MCP 클라이언트 설정 (Cursor)

`.cursor/mcp.json` 파일에 다음 설정 추가:

```json
{
    "mcpServers": {
        "Python MCP Server (Docker exec)": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-python-server-docker",
                "uv",
                "run",
                "/workspace/custom_mcp_server.py"
            ]
        },
        "OAuth2 MCP Tools": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-python-server-docker",
                "uv",
                "run",
                "/workspace/oauth2-demo/core/oauth2_mcp_tools.py"
            ]
        },
        "Security MCP Tools": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-python-server-docker",
                "uv",
                "run",
                "/workspace/oauth2-demo/security/secure_mcp_tools.py"
            ]
        },
        "Context7 MCP (Docker exec)": {
            "command": "docker",
            "args": [
                "exec",
                "-i",
                "mcp-node-server-docker",
                "npx",
                "-y",
                "@upstash/context7-mcp@latest"
            ]
        }
    }
}
```

### 6.5. 사용 가능한 MCP 도구들

#### OAuth2 도구들
- `get_oauth2_server_status`: OAuth2 서버 상태 확인
- `create_oauth2_test_token`: 테스트용 JWT 토큰 생성
- `get_oauth2_flow_guide`: OAuth2 플로우 가이드 제공
- `validate_oauth2_setup`: 전체 OAuth2 설정 검증

#### 보안 도구들
- `test_pii_detection`: PII 탐지 및 마스킹 테스트
- `test_encryption`: 데이터 암호화/복호화 테스트
- `get_security_audit_log`: 보안 감사 로그 조회
- `simulate_data_breach_detection`: 데이터 유출 탐지 시뮬레이션
- `generate_security_report`: 종합 보안 리포트 생성

------------------


## 7. 문제 해결 및 디버깅

### 7.1. 일반적인 MCP 서버 문제

MCP 서버가 예상대로 작동하지 않을 경우, Docker 컨테이너의 로그를 확인하여 문제를 진단할 수 있습니다.

-   **컨테이너 로그 확인**:
    ```bash
    docker logs <컨테이너_이름>
    # 예시:
    docker logs mcp-node-server-docker
    docker logs mcp-python-server-docker
    docker logs mcp-oauth2-web-server
    ```
    이 명령은 컨테이너가 시작된 이후 표준 출력(stdout) 및 표준 오류(stderr)로 내보낸 모든 로그를 보여줍니다.

-   **Docker Compose 전체 로그 확인**:
    ```bash
    # 전체 서비스 로그
    docker-compose logs

    # 특정 서비스 로그
    docker-compose logs oauth2-web-server

    # 실시간 로그 확인
    docker-compose logs -f
    ```

### 7.2. OAuth2 관련 문제 해결

-   **OAuth2 서버 연결 실패**:
    ```bash
    # 서버 상태 확인
    curl http://localhost:8081/.well-known/openid-configuration
    
    # 컨테이너 상태 확인
    docker ps | grep oauth2
    
    # OAuth2 서버 로그 확인
    docker logs mcp-oauth2-web-server
    ```

-   **401 Unauthorized 오류**:
    - 토큰이 없거나 잘못된 경우
    - 토큰 만료 확인
    - 올바른 스코프(`mcp.access`) 포함 여부 확인

-   **400 Bad Request 오류**:
    - Content-Type이 `application/x-www-form-urlencoded`인지 확인
    - 필수 파라미터(`grant_type`, `client_id`, `client_secret`) 포함 여부 확인

### 7.3. 보안 기능 디버깅

-   **보안 감사 로그 확인**:
    ```bash
    # 실시간 보안 로그 모니터링
    tail -f oauth2-demo/logs/security_audit.log
    
    # 특정 시간대 로그 확인
    grep "2025-01-06T12" oauth2-demo/logs/security_audit.log
    
    # PII 탐지 이벤트만 확인
    grep "contains_pii.*true" oauth2-demo/logs/security_audit.log
    ```

-   **PII 탐지 문제**:
    ```bash
    # PII 패턴 파일 확인
    cat oauth2-demo/security/pii_patterns.json
    
    # PII 탐지 테스트
    python -c "
    from oauth2_demo.security.security_common import get_pii_detector
    detector = get_pii_detector()
    print(detector.scan_text('테스트 이메일: test@example.com'))
    "
    ```

-   **암호화 키 문제**:
    ```bash
    # 암호화 키 디렉토리 확인
    ls -la oauth2-demo/keys/
    ls -la oauth2-demo/tests/keys/
    
    # 키 권한 확인
    chmod 600 oauth2-demo/keys/encryption.key
    ```

### 7.4. MCP 도구 연결 문제

-   **MCP 도구 응답 없음**:
    ```bash
    # 직접 MCP 도구 테스트
    docker exec -i mcp-python-server-docker uv run /workspace/oauth2-demo/core/oauth2_mcp_tools.py
    
    # Cursor에서 MCP 서버 재시작
    # Ctrl+Shift+P → "MCP: Restart Server"
    ```

-   **가상환경 문제**:
    ```bash
    # 가상환경 확인
    source .venv/bin/activate
    which python
    
    # 의존성 재설치
    uv pip install -r requirements.txt
    ```

### 7.5. 통합 테스트로 전체 상태 확인

```bash
# 전체 시스템 상태 확인 스크립트
./scripts/health_check.sh

# 또는 수동으로 순차 테스트
source .venv/bin/activate
python oauth2-demo/tests/test_oauth2_demo.py
python oauth2-demo/tests/test_mcp_tools_direct.py
python oauth2-demo/tests/test_mcp_integration.py
```

------------------


