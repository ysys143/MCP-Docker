# MCP 서버 도커 실행 및 클라이언트 설정 가이드


![How Docker Revolutionizes MCP](docker-mcp.png)
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
docker run -d --name mcp-server-docker -it node:20-slim bash
```

> **참고**: `--name` 옵션으로 지정된 컨테이너 이름(`mcp-server-docker`)은 Docker 호스트 내에서 고유해야 합니다. 같은 이름의 컨테이너가 이미 실행 중이거나 중지된 상태라면 새 컨테이너를 시작할 수 없습니다. 이 경우 기존 컨테이너를 중지 및 제거하거나 다른 이름을 사용해야 합니다.


## 3. MCP 클라이언트 설정 (.cursor/mcp.json 예시)

MCP 클라이언트(예: Cursor)는 `mcp.json` 파일을 통해 Context7 Documentation MCP 서버에 연결하는 방법을 설정합니다. 이 파일은 일반적으로 클라이언트의 설정 디렉토리(`~/.cursor/mcp.json` 등)에 위치하며, **Docker 컨테이너 내부로 복사되지 않습니다.**

이 설정 방식은 `docker exec`를 사용하여 컨테이너 내부에서 직접 MCP 서버 스크립트를 호출하므로, 별도의 포트 매핑(`-p` 옵션)이 필요 없습니다.

**컨테이너 내부 명령어 실행 확인 (선택 사항):**
MCP 서버가 컨테이너 내에서 제대로 구동 준비가 되었는지 확인하려면, 다음 명령으로 컨테이너 내부에 접속하여 MCP 서버 스크립트를 직접 실행해볼 수 있습니다:

```bash
docker exec -it mcp-server-docker bash
# (컨테이너 내부에서) npx -y @upstash/context7-mcp@latest
# 또는 Python 기반 서버의 경우:
# docker exec -it mcp-uv-server-docker bash
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
                "mcp-server-docker",
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
                "mcp-server-docker",
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
docker stop mcp-server-docker
docker rm mcp-server-docker
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
docker run -d --name mcp-server-docker -it node-base-image
```

-   `-d`: 컨테이너를 백그라운드에서 실행합니다.
-   `--name mcp-server-docker`: 컨테이너에 `mcp-server-docker`라는 이름을 지정합니다.
    > **참고**: `--name` 옵션으로 지정된 컨테이너 이름(`mcp-server-docker`)은 Docker 호스트 내에서 고유해야 합니다. 같은 이름의 컨테이너가 이미 실행 중이거나 중지된 상태라면 새 컨테이너를 시작할 수 없습니다. 이 경우 기존 컨테이너를 중지 및 제거하거나 다른 이름을 사용해야 합니다.
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
docker run -d --name mcp-uv-server-docker -it python-mcp-base-image
```

-   `-d`: 컨테이너를 백그라운드에서 실행합니다.
-   `--name mcp-uv-server-docker`: 컨테이너에 `mcp-uv-server-docker`라는 이름을 지정합니다.
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
                "mcp-uv-server-docker",
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
docker stop mcp-uv-server-docker
docker rm mcp-uv-server-docker
```


------------------


## 6. 문제 해결 및 디버깅

MCP 서버가 예상대로 작동하지 않을 경우, Docker 컨테이너의 로그를 확인하여 문제를 진단할 수 있습니다.

-   **컨테이너 로그 확인**:
    ```bash
    docker logs <컨테이너_이름>
    # 예시:
    # docker logs mcp-server-docker
    # docker logs mcp-uv-server-docker
    ```
    이 명령은 컨테이너가 시작된 이후 표준 출력(stdout) 및 표준 오류(stderr)로 내보낸 모든 로그를 보여줍니다. 서버의 시작 과정, 오류 메시지, 처리된 요청 등을 확인할 수 있습니다.

------------------


