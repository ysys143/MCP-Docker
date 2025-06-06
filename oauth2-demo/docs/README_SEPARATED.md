# OAuth2 데모 - 분리된 구조

> **명확한 역할 분리**: 웹 서버와 MCP 도구를 별도로 분리하여 혼동을 제거했습니다.

## 📁 파일 구조

```
oauth2-demo/
├── oauth2_common.py        # 공통 로직 (JWT, 인증)
├── oauth2_web_server.py    # HTTP 웹 서버 (FastAPI)
├── oauth2_mcp_tools.py     # MCP 도구 (stdio JSON-RPC)
├── test_oauth2_demo.py     # 테스트 스크립트
└── README_SEPARATED.md     # 이 문서
```

## 🔧 역할별 분리

### 1️⃣ **공통 로직** (`oauth2_common.py`)
```python
# JWT 토큰 생성/검증, 클라이언트 인증 등
- create_jwt_token()
- verify_jwt_token() 
- authenticate_client()
- create_test_token_data()
```

### 2️⃣ **웹 서버** (`oauth2_web_server.py`) 
```python
# FastAPI 기반 HTTP API 서버
- OAuth2 토큰 발급: POST /oauth2/token
- 보호된 리소스: GET /hello, GET /
- OpenID Connect: GET /.well-known/openid-configuration
- JWKS: GET /.well-known/jwks.json
```

**실행 방식**: 
- **Docker**: 포트 8081에서 계속 실행
- **로컬**: `python oauth2_web_server.py`

### 3️⃣ **MCP 도구** (`oauth2_mcp_tools.py`)
```python
# FastMCP 기반 stdio JSON-RPC 서버
- get_oauth2_server_status()     # 서버 상태 조회
- create_oauth2_test_token()     # 테스트 토큰 생성
- get_oauth2_flow_guide()        # OAuth2 플로우 가이드
- validate_oauth2_setup()        # 서버 설정 검증
```

**실행 방식**:
- **MCP 클라이언트**: Cursor에서 "OAuth2 MCP Tools" 선택
- **직접 실행**: `python oauth2_mcp_tools.py` (stdio 대기)

## 🚀 사용법

### **웹 서버 테스트**
```bash
# 서버 상태 확인
curl http://localhost:8081/.well-known/openid-configuration

# 토큰 획득
curl -X POST http://localhost:8081/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access'

# 보호된 리소스 접근
curl -H 'Authorization: Bearer <TOKEN>' http://localhost:8081/hello

# 자동 테스트
python test_oauth2_demo.py
```

### **MCP 도구 사용**
1. **Cursor에서**: `Ctrl+Shift+P` → "MCP" → "OAuth2 MCP Tools" 선택
2. **사용 가능한 도구들**:
   - `get_oauth2_server_status`: 서버 상태 확인
   - `create_oauth2_test_token`: 테스트 토큰 생성
   - `get_oauth2_flow_guide`: OAuth2 플로우 가이드
   - `validate_oauth2_setup`: 설정 검증

## 🐳 Docker 실행

### **웹 서버만 실행**
```bash
docker-compose up -d oauth2-web-server
```

### **MCP 도구 사용** (Python 서버 필요)
```bash
docker-compose up -d python-server
# Cursor에서 MCP 도구 사용
```

### **전체 실행**
```bash
docker-compose up -d
```

## ✅ 이점

### **기존 구조의 문제점**
```python
# mcp_oauth2_server.py (혼합형)
app = FastAPI()        # 웹 서버
mcp = FastMCP()        # MCP 도구

if __name__ == "__main__":
    uvicorn.run(app)   # 웹서버로 실행
    # 그런데 MCP에서는 stdio로 실행?? 🤔
```

### **분리된 구조의 장점**
1. **명확한 역할**: 웹 서버 vs MCP 도구
2. **실행 방식 명확**: HTTP vs stdio JSON-RPC  
3. **혼동 제거**: 각각 다른 목적과 프로토콜
4. **유지보수 용이**: 독립적인 테스트와 배포
5. **MCP 표준 준수**: 순수 stdio JSON-RPC

## 🧪 테스트 결과

### **웹 서버 테스트** (7/7 통과)
- ✅ 서버 상태 확인
- ✅ OpenID Connect Discovery  
- ✅ JWKS 엔드포인트
- ✅ OAuth2 토큰 획득
- ✅ 보호된 엔드포인트 접근
- ✅ 인증 없는 접근 차단
- ✅ 잘못된 토큰 거부

### **MCP 도구**
- ✅ mcp.json에 "OAuth2 MCP Tools" 등록
- ✅ 4개 도구 제공
- ✅ stdio JSON-RPC 프로토콜 준수

## 🔗 관련 파일

- **설정**: `.cursor/mcp.json` - MCP 도구 등록
- **Docker**: `docker-compose.yml` - 웹 서버 컨테이너
- **테스트**: `test_oauth2_demo.py` - 웹 서버 검증
- **공통**: `oauth2_common.py` - 재사용 가능한 로직 