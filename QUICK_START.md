# 🚀 빠른 시작 가이드

재솔님을 위한 MCP Docker 프로젝트 빠른 시작 가이드입니다!

## 📦 전체 프로젝트 실행 (Docker Compose)

가장 간단한 방법으로 모든 서비스를 한 번에 실행하세요:

```bash
# 모든 서비스 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 서비스 중지
docker-compose down
```

## 🔐 OAuth2 데모 서버만 실행

```bash
# OAuth2 데모 디렉토리로 이동
cd oauth2-demo

# 직접 실행
python mcp_oauth2_server.py

# 또는 Docker로 실행
docker build -t mcp-oauth2-demo .
docker run -p 8081:8081 mcp-oauth2-demo

# 테스트 실행
python test_oauth2_demo.py
```

## 🛠️ 개별 컴포넌트 테스트

### 1. OAuth2 토큰 획득
```bash
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"
```

### 2. 보호된 엔드포인트 접근
```bash
# 위에서 받은 토큰을 사용
curl -H "Authorization: Bearer <YOUR_TOKEN>" http://localhost:8081/hello
```

### 3. 메인 MCP 서버 테스트
```bash
# Python 기반 MCP 서버 실행
docker exec -it mcp-uv-server-docker uv run /app/examples/custom_mcp_server.py

# Node.js 기반 MCP 서버 실행  
docker exec -it mcp-server-docker npx -y @upstash/context7-mcp@latest
```

## 📝 MCP 클라이언트 설정

Cursor나 다른 MCP 클라이언트에서 사용하려면 `~/.cursor/mcp.json`에 추가:

```json
{
    "mcpServers": {
        "OAuth2 Demo": {
            "command": "python",
            "args": ["/path/to/oauth2-demo/mcp_oauth2_server.py"]
        },
        "Context7 MCP (Docker)": {
            "command": "docker",
            "args": ["exec", "-i", "mcp-server-docker", "npx", "-y", "@upstash/context7-mcp@latest"]
        },
        "Python Weather MCP (Docker)": {
            "command": "docker", 
            "args": ["exec", "-i", "mcp-uv-server-docker", "uv", "run", "/app/examples/custom_mcp_server.py"]
        }
    }
}
```

## 🔧 개발 환경 설정

```bash
# 의존성 설치 (uv 사용)
uv pip install -r requirements.txt

# 또는 pip 사용
pip install -r requirements.txt

# 개발 서버 실행
cd oauth2-demo
uvicorn mcp_oauth2_server:app --reload --host 0.0.0.0 --port 8081
```

## 📚 주요 디렉토리

- **`oauth2-demo/`** - OAuth2 인증 데모 서버
- **`docs/`** - 문서 및 보안 가이드  
- **`docker/`** - Docker 설정 파일들
- **`scripts/`** - 유틸리티 스크립트들
- **`examples/`** - 예제 MCP 서버들

## 🆘 문제 해결

### 포트 충돌
```bash
# 포트 사용 확인
lsof -i :8081
lsof -i :8080

# 프로세스 종료
kill -9 <PID>
```

### Docker 컨테이너 정리
```bash
# 모든 컨테이너 중지
docker stop $(docker ps -aq)

# 사용하지 않는 컨테이너 제거
docker container prune

# 특정 컨테이너 재시작
docker restart mcp-oauth2-demo
```

### 로그 확인
```bash
# OAuth2 서버 로그
docker logs mcp-oauth2-demo

# 메인 MCP 서버 로그  
docker logs mcp-server-docker
```

이제 바로 시작하실 수 있습니다! 🎊 