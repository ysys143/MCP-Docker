FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필수 도구 설치
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 파일 복사
COPY requirements.txt /app/

# UV 설치
RUN pip install uv

# 의존성 설치
RUN uv pip install --system -r requirements.txt

# 프로젝트 파일 복사
COPY . /app/

# 포트 노출
EXPOSE 8081

# 환경 변수 설정
ENV JWT_SECRET_KEY="mcp-oauth2-demo-secret-key-2025"
ENV PYTHONPATH="/app"

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/.well-known/openid-configuration || exit 1

# 웹 서버 시작 명령
CMD ["python", "oauth2-demo/core/oauth2_web_server.py"] 