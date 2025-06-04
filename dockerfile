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
# 만약 빌드 과정이 필요하다면 여기에 추가
# RUN python custom_mcp_server.py build # 예시

# 로깅 쉘 스크립트 복사 및 실행 권한 부여
COPY run_mcp_server_with_logging.sh .
RUN chmod +x run_mcp_server_with_logging.sh

CMD ["tail", "-f", "/dev/null"]