# MCP OAuth2 데모

Microsoft의 [MCP for beginners OAuth2 데모](https://github.com/microsoft/mcp-for-beginners/tree/main/05-AdvancedTopics/mcp-oauth2-demo)를 Python으로 구현한 버전입니다.

## 개요

이 프로젝트는 **최소한의 FastAPI 애플리케이션**으로, 다음 두 가지 역할을 모두 수행합니다:

- **OAuth2 Authorization Server** (client_credentials 플로우를 통한 JWT 액세스 토큰 발급)
- **Resource Server** (자체 `/hello` 엔드포인트 보호)

## 주요 기능

### OAuth2 인증
- ✅ OAuth2 client_credentials 플로우
- ✅ JWT 토큰 발급 및 검증
- ✅ 보호된 MCP 엔드포인트
- ✅ FastMCP 인증 시스템 통합
- ✅ OpenID Connect Discovery 지원
- ✅ JWKS 엔드포인트 제공

### 🔐 엔터프라이즈 보안 기능
- ✅ **PII (개인식별정보) 탐지 및 마스킹**: 자동으로 민감한 정보 식별 및 보호
- ✅ **데이터 암호화/복호화**: Fernet 알고리즘을 사용한 민감한 데이터 보호
- ✅ **보안 감사 로깅**: 모든 도구 접근 및 보안 이벤트 추적
- ✅ **보안 정책 적용**: PII 발견 시 암호화, 마스킹, 거부 정책 선택
- ✅ **통합 보안 아키텍처**: OAuth2 인증과 데이터 보호의 완전한 통합

## 빠른 시작 (로컬)

### 1. 의존성 설치

```bash
# uv를 사용한 의존성 설치
uv pip install fastapi uvicorn pyjwt python-jose[cryptography] fastmcp python-multipart httpx

# 또는 pip 사용
pip install fastapi uvicorn pyjwt python-jose[cryptography] fastmcp python-multipart httpx
```

### 2. 서버 실행

```bash
# 직접 실행
python mcp_oauth2_server.py

# 또는 uvicorn 사용
uvicorn mcp_oauth2_server:app --host 0.0.0.0 --port 8081
```

### 3. OAuth2 플로우 테스트

#### 토큰 획득
```bash
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"
```

#### 보호된 엔드포인트 호출
```bash
# 위에서 받은 토큰을 사용
curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" http://localhost:8081/hello
```

## Docker로 실행

### 이미지 빌드 및 실행

```bash
# Docker 이미지 빌드
docker build -f dockerfile.oauth2 -t mcp-oauth2-demo .

# 컨테이너 실행
docker run -p 8081:8081 mcp-oauth2-demo
```

## OAuth2 설정 테스트

OAuth2 보안 설정을 다음 단계로 테스트할 수 있습니다:

### 1. 서버 실행 및 보안 확인

```bash
# 401 Unauthorized를 반환해야 함 (OAuth2 보안이 활성화된 것을 확인)
curl -v http://localhost:8081/
```

### 2. client_credentials를 사용한 액세스 토큰 획득

```bash
# 전체 토큰 응답 확인
curl -v -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"

# 토큰만 추출 (jq 필요)
curl -s -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access" | jq -r .access_token > token.txt
```

### 3. 토큰을 사용한 보호된 엔드포인트 접근

```bash
# 저장된 토큰 사용
curl -H "Authorization: Bearer $(cat token.txt)" http://localhost:8081/hello

# 직접 토큰 입력
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." http://localhost:8081/hello
```

성공적인 응답으로 "MCP OAuth2 데모에서 안녕하세요!"가 반환되면 OAuth2 설정이 올바르게 작동하는 것입니다.

## 자동 테스트 실행

전체 OAuth2 플로우를 자동으로 테스트하려면:

```bash
python test_oauth2_demo.py
```

이 스크립트는 다음을 테스트합니다:
- 서버 상태 확인
- OpenID Connect Discovery
- JWKS 엔드포인트
- 토큰 획득
- 보호된 엔드포인트 접근
- 인증 없는 접근 차단
- 잘못된 토큰 거부

## 🔐 보안 기능 사용법

### 보안 통합 테스트 실행

OAuth2 인증과 모든 보안 기능을 통합적으로 테스트하려면:

```bash
python test_security_integration.py
```

이 스크립트는 다음을 포괄적으로 테스트합니다:
- PII 탐지 및 마스킹 기능
- 데이터 암호화/복호화
- 보안 감사 로깅
- OAuth2 인증과 보안 기능 통합
- 실제 기업 환경 시나리오 시뮬레이션

### 보안 MCP 도구 실행

보안이 적용된 MCP 도구들을 테스트하려면:

```bash
python secure_mcp_tools.py
```

사용 가능한 보안 도구들:
- **`get_user_info`**: 사용자 정보 조회 (PII 자동 마스킹)
- **`store_sensitive_data`**: 민감한 데이터 저장 (자동 암호화)
- **`high_security_operation`**: 고보안 작업 (PII 발견 시 거부)
- **`test_pii_detection`**: PII 탐지 테스트
- **`test_encryption`**: 암호화/복호화 테스트
- **`get_security_audit_log`**: 보안 감사 로그 조회
- **`simulate_data_breach_detection`**: 데이터 유출 탐지 시뮬레이션
- **`generate_security_report`**: 보안 리포트 생성

### PII 탐지 및 마스킹 예제

```python
from security_common import get_pii_detector

pii_detector = get_pii_detector()

# PII 탐지
text = "고객 정보: 홍길동님 (hong@example.com, 010-1234-5678)"
detected_pii = pii_detector.scan_text(text)
print(f"탐지된 PII: {detected_pii}")

# PII 마스킹
masked_text = pii_detector.mask_pii(text)
print(f"마스킹된 텍스트: {masked_text}")
```

### 데이터 암호화 예제

```python
from security_common import get_encryption_service

encryption_service = get_encryption_service()

# 민감한 데이터 암호화
sensitive_data = "고객 이메일: customer@company.com"
encrypted = encryption_service.encrypt(sensitive_data)
print(f"암호화된 데이터: {encrypted[:30]}...")

# 데이터 복호화
decrypted = encryption_service.decrypt(encrypted)
print(f"복호화된 데이터: {decrypted}")
```

### 보안 도구 데코레이터 사용법

```python
from security_common import secure_tool

@secure_tool(requires_encryption=True, log_access=True, pii_policy="encrypt")
async def process_customer_data(customer_info: str, client_id: str, user_id: str):
    # PII가 자동으로 탐지되고 암호화됨
    # 모든 접근이 감사 로그에 기록됨
    return {"status": "processed", "data": customer_info}
```

### 보안 정책 옵션

보안 도구 데코레이터에서 지원하는 PII 정책:

- **`"encrypt"`**: PII 발견 시 자동 암호화 (기본값)
- **`"mask"`**: PII 발견 시 마스킹 처리
- **`"reject"`**: PII 발견 시 요청 거부

### 보안 감사 로그

모든 보안 이벤트는 `logs/security_audit.log`에 기록됩니다:

```json
{
  "timestamp": "2025-01-06T12:34:56",
  "event_type": "tool_access",
  "tool_name": "store_sensitive_data",
  "user_id": "user123",
  "client_id": "mcp-client",
  "contains_pii": true,
  "action_taken": "executed_with_encryption"
}
```

## API 엔드포인트

### OAuth2 엔드포인트

| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/oauth2/token` | POST | OAuth2 토큰 발급 |
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |

### 보호된 리소스

| 엔드포인트 | 메서드 | 설명 | 인증 필요 |
|-----------|--------|------|----------|
| `/` | GET | 서버 정보 | ✅ |
| `/hello` | GET | 인사 메시지 | ✅ |

## 설정

### 환경 변수

- `JWT_SECRET_KEY`: JWT 토큰 서명에 사용할 시크릿 키 (기본값: "mcp-oauth2-demo-secret-key-2025")

### 클라이언트 자격 증명

현재 설정된 OAuth2 클라이언트:
- **Client ID**: `mcp-client`
- **Client Secret**: `secret`
- **Grant Type**: `client_credentials`
- **Scope**: `mcp.access`

> ⚠️ **주의**: 운영 환경에서는 안전한 클라이언트 시크릿을 사용하세요.

## MCP 통합

이 서버는 FastMCP를 사용하여 다음 MCP 도구를 제공합니다:

### `get_server_status`
서버의 현재 상태와 사용 가능한 엔드포인트 정보를 반환합니다.

### `create_test_token`
테스트용 OAuth2 토큰을 생성하고 사용 예제를 제공합니다.

## 보안 고려사항

1. **JWT 시크릿**: 운영 환경에서는 강력한 시크릿 키를 사용하세요.
2. **클라이언트 자격 증명**: 안전한 클라이언트 시크릿을 사용하세요.
3. **HTTPS**: 운영 환경에서는 HTTPS를 사용하세요.
4. **토큰 만료**: 현재 토큰 만료 시간은 30분입니다.

## Azure Container Apps에 배포

```bash
# Azure CLI 로그인
az login

# 컨테이너 앱 생성
az containerapp up -n mcp-oauth2 \
  -g demo-rg -l westeurope \
  --image <your-registry>/mcp-oauth2-demo:latest \
  --ingress external --target-port 8081
```

FQDN이 **issuer**가 됩니다 (`https://<fqdn>`).
Azure는 `*.azurecontainerapps.io`에 대해 신뢰할 수 있는 TLS 인증서를 자동으로 제공합니다.

## Azure API Management와 연동

API에 다음 인바운드 정책을 추가하세요:

```xml
<inbound>
  <validate-jwt header-name="Authorization">
    <openid-config url="https://<fqdn>/.well-known/openid-configuration"/>
    <audiences>
      <audience>mcp-client</audience>
    </audiences>
  </validate-jwt>
  <base/>
</inbound>
```

APIM이 JWKS를 가져와서 모든 요청을 검증합니다.

## 문제 해결

### 일반적인 문제

1. **401 Unauthorized**: 토큰이 없거나 잘못됨
   - 올바른 토큰을 요청했는지 확인
   - 토큰이 만료되지 않았는지 확인

2. **400 Bad Request**: 잘못된 요청 형식
   - Content-Type이 `application/x-www-form-urlencoded`인지 확인
   - 필수 파라미터가 모두 포함되었는지 확인

3. **서버 연결 실패**:
   - 서버가 실행 중인지 확인: `curl http://localhost:8081/.well-known/openid-configuration`
   - 포트 8081이 사용 가능한지 확인

## 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다.

## 기여

버그 리포트나 기능 요청은 GitHub Issues를 사용해 주세요.

## 참고 자료

- [Microsoft MCP for beginners OAuth2 데모](https://github.com/microsoft/mcp-for-beginners/tree/main/05-AdvancedTopics/mcp-oauth2-demo)
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [FastAPI OAuth2 문서](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [FastMCP 문서](https://github.com/jlowin/fastmcp) 