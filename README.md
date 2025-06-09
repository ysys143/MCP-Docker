# MCP Server Docker Execution and Client Setup Guide

## Project Structure

```
mcp-docker/
├── oauth2-demo/                    # 🔐 OAuth2 + Security Demo Server
│   ├── core/                       #   Core OAuth2 modules
│   │   ├── mcp_oauth2_server.py   #     Integrated OAuth2 FastAPI server
│   │   ├── oauth2_web_server.py   #     Separated OAuth2 web server
│   │   ├── oauth2_mcp_tools.py    #     OAuth2 MCP tools
│   │   └── oauth2_common.py       #     JWT token & auth common logic
│   ├── security/                   #   Security feature modules
│   │   ├── security_common.py     #     PII detection, encryption, audit logging
│   │   ├── secure_mcp_tools.py    #     Security-enabled MCP tools
│   │   └── pii_patterns.json      #     PII pattern definitions
│   ├── tests/                      #   Comprehensive test suite
│   │   ├── test_oauth2_demo.py    #     OAuth2 flow tests
│   │   ├── test_mcp_tools_direct.py #   Direct MCP tool tests
│   │   ├── test_mcp_integration.py #    MCP integration tests
│   │   ├── test_security_integration.py # Security integration tests
│   │   ├── keys/                  #     Test encryption keys
│   │   └── logs/                  #     Test audit logs
│   ├── config/                     #   Configuration files
│   │   └── Dockerfile             #     Dockerfile for OAuth2 server
│   ├── docs/                       #   OAuth2 detailed documentation
│   │   ├── README.md              #     Complete OAuth2 guide
│   │   └── README_SEPARATED.md    #     Separated structure explanation
│   ├── keys/                       #   JWT encryption key storage
│   ├── logs/                       #   Security audit logs
│   │   └── security_audit.log     #     Real-time security event logs
│   ├── README.md                   #   OAuth2 demo main documentation
│   └── __init__.py                 #   Python package initialization
├── docker/                         # Docker related files
│   └── dockerfile                  #   Dockerfile for main Python MCP server
├── scripts/                        # Execution scripts
│   └── run_mcp_server_with_logging.sh # MCP server logging script
├── examples/                       # Example files
│   └── custom_mcp_server.py        #   Basic MCP server example
├── .cursor/                        # Cursor IDE configuration
│   └── mcp.json                    #   MCP client configuration
├── .venv/                          # Python virtual environment (uv)
├── docker-compose.yml              # 🐳 Docker Compose integrated configuration
│                                   #   - mcp-python-server-docker (port 8080)
│                                   #   - mcp-oauth2-web-server (port 8081)
│                                   #   - mcp-node-server-docker
├── requirements.txt                # Python dependency packages
├── QUICK_START.md                  # Quick start guide
├── README_KOR.md                   # 📖 Korean main documentation
└── README.md                       # 📖 English main documentation (this file)
```

[Korean Version (한국어 버전)](README_KOR.md)

[Docker Blog: How to build and deliver an MCP server for production](https://www.docker.com/blog/build-to-prod-mcp-servers-with-docker/)

### 🏗️ Architecture Overview

#### Overall System Architecture

![System Architecture](charts/system-architecture.png)

#### 1️⃣ **Main MCP Server Stack**
- **Python MCP Server**: Main MCP tools running on port 8080
- **Node.js MCP Server**: Node.js-based tools like Context7, sequential-thinking
- **Docker Isolation**: Each server runs safely in independent containers

#### 2️⃣ **OAuth2 + Security Stack**
- **OAuth2 Authorization Server**: JWT token issuance (client_credentials flow)
- **OAuth2 Resource Server**: Protected MCP endpoint provision
- **PII Detection & Masking**: Automatic identification and protection of personally identifiable information
- **Data Encryption**: Sensitive data protection based on Fernet algorithm
- **Security Audit Logging**: Real-time tracking of all security events

#### 3️⃣ **Integrated Test System**
- **OAuth2 Flow Testing**: Token issuance, authentication, protected resource access
- **MCP Tool Testing**: Direct calls and integration scenario testing
- **Security Integration Testing**: PII detection, encryption, audit logging verification
- **Automated CI/CD**: Continuous verification of all functionalities

#### Docker Network Configuration

![Docker Network](charts/system-architecture.png)

## 🔐 OAuth2 and Security Authentication Workflow

### OAuth2 Client Credentials Flow

This project implements server-to-server authentication using **OAuth2 Client Credentials Grant**.

#### 1️⃣ **Authentication Flow Steps**

![OAuth2 Authentication Flow](charts/oauth2-flow.png)

#### 2️⃣ **Detailed Implementation**

##### **Token Issuance Process**
```bash
# Step 1: Client authentication and token request
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"

# Response: JWT Token
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "mcp.access"
}
```

##### **JWT Token Structure**
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "mcp-client",           // Client ID
    "aud": "mcp-client",           // Target service
    "scope": "mcp.access",         // Permission scope
    "exp": 1704533400,             // Expiration time
    "iat": 1704531600,             // Issued at
    "jti": "unique-token-id"       // Unique token ID
  },
  "signature": "HMACSHA256(...)"   // Signature
}
```

### 🛡️ Multi-layered Security Architecture

#### Security Processing Flow

![Security Processing Flow](charts/security-flow.png)

#### Security Layer Structure

![Security Processing Flow](charts/security-flow.png)

#### 1️⃣ **PII (Personally Identifiable Information) Detection System**

```python
# PII Pattern Definitions (pii_patterns.json)
{
  "email": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
  "phone": "\\b01[0-9]-?[0-9]{4}-?[0-9]{4}\\b",
  "korean_name": "\\b[가-힣]{2,4}\\b(?=님|씨|\\s|$)",
  "ssn": "\\b\\d{6}-?[1-4]\\d{6}\\b"
}

# Real-time PII detection and processing
def scan_and_process_pii(text: str, policy: str = "encrypt"):
    detected_pii = pii_detector.scan_text(text)
    
    if detected_pii:
        if policy == "encrypt":
            return encryption_service.encrypt(text)
        elif policy == "mask":
            return pii_detector.mask_pii(text)
        elif policy == "reject":
            raise SecurityException("Request rejected due to PII content")
    
    return text
```

#### 2️⃣ **Data Encryption System**

```python
# Using Fernet symmetric encryption
from cryptography.fernet import Fernet

class EncryptionService:
    def __init__(self):
        self.fernet = Fernet(self._load_or_generate_key())
    
    def encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        encrypted = self.fernet.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt encrypted data"""
        decoded = base64.b64decode(encrypted_data.encode())
        decrypted = self.fernet.decrypt(decoded)
        return decrypted.decode()
```

#### 3️⃣ **Security Audit Logging**

```python
# Real-time recording of all security events
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
    
    # Record in JSON format to security audit log
    security_logger.info(json.dumps(log_entry, ensure_ascii=False))
```

### 🔄 Real Authentication Flow Examples

#### MCP Tool Invocation Flow

![MCP Execution Flow](charts/mcp-execution-flow.png)

#### Data Processing Flow

![MCP Execution Flow](charts/mcp-execution-flow.png)

#### **When Calling MCP Tools from Cursor**

```bash
# 1. Cursor calls MCP tool in Docker container
docker exec -i mcp-python-server-docker uv run /workspace/oauth2-demo/core/oauth2_mcp_tools.py

# 2. MCP tool requests token from OAuth2 server
POST http://localhost:8081/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access

# 3. OAuth2 server issues JWT token
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800
}

# 4. MCP tool accesses protected resources with token
GET http://localhost:8081/hello
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 5. Server validates token and responds
{
  "message": "Hello from MCP OAuth2 Demo!",
  "authenticated_client": "mcp-client",
  "timestamp": "2025-01-06T12:34:56"
}
```

### 🔒 Security Policy Options

| Policy | Description | Use Case |
|--------|-------------|----------|
| `encrypt` | Automatically encrypt data when PII is detected | Sensitive data storage/transmission |
| `mask` | Mask PII (****) and proceed | Logging, debugging, preview |
| `reject` | Immediately reject request when PII is detected | High-security environments, compliance |

![How Docker Revolutionizes MCP](docs/docker-mcp.png)
[Docker Blog: How to build and deliver an MCP server for production](https://www.docker.com/blog/build-to-prod-mcp-servers-with-docker/)

Problems with the Existing MCP (Model Context Protocol) Workflow

*   **Complex Management**: Each MCP client had to run its own copy of every MCP server at all times, which consumed excessive local resources. Clients had to directly configure their server sets, it was difficult to figure out which MCP servers to use, and some MCP servers had compatibility issues that prevented them from working on certain agents.
*   **Dependency Hell**: MCP servers only worked if all runtimes and dependencies were installed. Agents had direct access to host resources, which could pose security risks.
*   **Security Issues**: API keys had to be manually configured in plaintext configuration files, and authentication server management was cumbersome.

By isolating the MCP server execution environment with Docker,

*   **Simplified Runtime**: Using Docker standardizes the installation of MCP tools with a single runtime application, which can significantly reduce management overhead.
*   **Isolation and Security**: Docker containers are effective at sandboxing agents, preventing unnecessary access to host resources. Furthermore, API keys can be managed securely without being stored in plaintext configuration files, and OAuth-based server authentication can be considered to enhance security.
*   **Easy Accessibility**: Clients can access MCP services through a single endpoint, providing flexibility for agents to use suitable tools for a task even if the user hasn't explicitly installed them.

# Setup Method

## 1. Prerequisites

-   Docker must be installed. You can install it from the [Official Docker Website](https://www.docker.com/get-started).

## 2. Docker Container Execution

Launch the node20 image with Docker.

```bash
docker run -d --name mcp-node-server-docker -it node:20-slim bash
```

> **Note**: The container name specified with the `--name` option (`mcp-node-server-docker`) must be unique within the Docker host. If a container with the same name is already running or stopped, a new container cannot be started. In this case, you must stop and remove the existing container or use a different name.

## 3. MCP Client Configuration (.cursor/mcp.json Example)

MCP clients (e.g., Cursor) configure how to connect to the Context7 Documentation MCP server via the `mcp.json` file. This file is typically located in the client's configuration directory (e.g., `~/.cursor/mcp.json`) and is **not copied into the Docker container.**

This setup uses `docker exec` to directly call the MCP server script inside the container, so no separate port mapping (`-p` option) is required.

**Verifying Command Execution Inside the Container (Optional):**
To check if the MCP server is properly ready for execution inside the container, you can access the container and try running the MCP server script directly with the following commands:

```bash
docker exec -it mcp-node-server-docker bash
# (Inside the container) npx -y @upstash/context7-mcp@latest
# Or for a Python-based server:
# docker exec -it mcp-python-server-docker bash
# (Inside the container) uv run /app/custom_mcp_server.py
```

You can configure the `mcp.json` file as follows to connect to the Context7 MCP Server running within the Docker container:

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

## 4. Stopping and Removing Containers (Optional)

To stop and remove containers, use the following commands:

```bash
docker stop mcp-node-server-docker
docker rm mcp-node-server-docker
```

Following this guide, you can easily deploy and configure the Context7 Documentation MCP Server in a Docker environment and utilize it with your client.

------------------

## 5. Custom Build Cases

### 5.1. Node.js Based MCP Server Custom Build

The Context7 Documentation MCP Server is Node.js based. You can build and run the server in a Node.js environment using the following `Dockerfile`.

```dockerfile
FROM node:20-slim
WORKDIR /app
CMD ["tail", "-f", "/dev/null"]
```

Build the Docker image by running the following command in the project root directory where the `Dockerfile` is located.
Tag the built image with a generic name like `node-base-image`.

```bash
docker build -t node-base-image .
```

Run the Docker container using the built image.

```bash
docker run -d --name mcp-node-server-docker -it node-base-image
```

-   `-d`: Runs the container in detached mode (in the background).
-   `--name mcp-node-server-docker`: Assigns the name `mcp-node-server-docker` to the container.
    > **Note**: The container name specified with the `--name` option (`mcp-node-server-docker`) must be unique within the Docker host. If a container with the same name is already running or stopped, a new container cannot be started. In this case, you must stop and remove the existing container or use a different name.
-   `-it`: Enables interactive mode for the container and allocates a TTY. This is useful when executing commands inside the container.
-   `node-base-image`: The name of the Docker image to run.

### 5.2. Python (`uv`) Based MCP Server Custom Build (Example)

If you are using a Python-based MCP server and managing dependencies with `uv`, you can configure a similar `Dockerfile` as follows. This example assumes that a `requirements.txt` file exists in your project root.

```dockerfile
FROM python:3.10-slim-buster
WORKDIR /app

# Install necessary system packages and clean up cache
RUN apt-get update && apt-get install -y --no-install-recommends curl tar \
    && rm -rf /var/lib/apt/lists/*

# Install uv (recommended)
# Download the latest uv binary and install it to /usr/local/bin.
RUN curl -sSfL https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv

# Install dependencies
COPY requirements.txt .
RUN uv pip install -r requirements.txt --system

# Copy and build MCP server script (if necessary)
# Example: Assuming you have a file named custom_mcp_server.py
COPY custom_mcp_server.py .
# custom_mcp_server.py should be an MCP server that handles JSON-RPC requests/responses via standard input (stdin) and standard output (stdout).

CMD ["tail", "-f", "/dev/null"]
```

Build the Docker image by running the following command in the project root directory where the `Dockerfile` is located.
Tag the built image with a generic name like `python-mcp-base-image`.

```bash
docker build -t python-mcp-base-image .
```

Run the Docker container using the built image.

```bash
docker run -d --name mcp-python-server-docker -it python-mcp-base-image
```

-   `-d`: Runs the container in detached mode (in the background).
-   `--name mcp-python-server-docker`: Assigns the name `mcp-python-server-docker` to the container.
-   `-it`: Enables interactive mode for the container and allocates a TTY.
-   `python-mcp-base-image`: The name of the Docker image to run.

Here's an example of `mcp.json` client configuration for running a Python-based MCP server within the container:

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
After adding this configuration, you should restart your MCP client (e.g., Cursor) to apply the changes.

To stop and remove containers, use the following commands:

```bash
docker stop mcp-python-server-docker
docker rm mcp-python-server-docker
```

------------------

## 6. OAuth2 + Security Demo Usage

### 6.1. Run Full Stack with Docker Compose

```bash
# Run full stack (Python + Node.js + OAuth2 server)
docker-compose up -d

# Run specific services only
docker-compose up -d mcp-server oauth2-web-server

# Check service status
docker-compose ps
```

### 6.2. OAuth2 Server Testing

```bash
# Check OAuth2 server status
curl http://localhost:8081/.well-known/openid-configuration

# Get token
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"

# Access protected endpoint
curl -H "Authorization: Bearer <token>" http://localhost:8081/hello
```

### 6.3. Security Feature Testing

```bash
# Activate virtual environment
source .venv/bin/activate

# Automated OAuth2 flow testing
python oauth2-demo/tests/test_oauth2_demo.py

# Direct MCP tool testing
python oauth2-demo/tests/test_mcp_tools_direct.py

# Security integration testing
python oauth2-demo/tests/test_mcp_integration.py
```

### 6.4. MCP Client Configuration (Cursor)

Add the following configuration to `.cursor/mcp.json` file:

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

### 6.5. Available MCP Tools

#### OAuth2 Tools
- `get_oauth2_server_status`: Check OAuth2 server status
- `create_oauth2_test_token`: Generate test JWT token
- `get_oauth2_flow_guide`: Provide OAuth2 flow guide
- `validate_oauth2_setup`: Validate complete OAuth2 setup

#### Security Tools
- `test_pii_detection`: Test PII detection and masking
- `test_encryption`: Test data encryption/decryption
- `get_security_audit_log`: View security audit logs
- `simulate_data_breach_detection`: Simulate data breach detection
- `generate_security_report`: Generate comprehensive security report

------------------

## 7. Troubleshooting and Debugging

### 7.1. General MCP Server Issues

If the MCP server is not working as expected, you can check the Docker container's logs to diagnose the issue.

-   **Check Container Logs**:
    ```bash
    docker logs <container_name>
    # Example:
    docker logs mcp-node-server-docker
    docker logs mcp-python-server-docker
    docker logs mcp-oauth2-web-server
    ```
    This command displays all logs output by the container to standard output (stdout) and standard error (stderr) since it started.

-   **Docker Compose Full Logs**:
    ```bash
    # Full service logs
    docker-compose logs

    # Specific service logs
    docker-compose logs oauth2-web-server

    # Real-time log monitoring
    docker-compose logs -f
    ```

### 7.2. OAuth2 Related Troubleshooting

-   **OAuth2 Server Connection Failure**:
    ```bash
    # Check server status
    curl http://localhost:8081/.well-known/openid-configuration
    
    # Check container status
    docker ps | grep oauth2
    
    # Check OAuth2 server logs
    docker logs mcp-oauth2-web-server
    ```

-   **401 Unauthorized Error**:
    - Missing or invalid token
    - Check token expiration
    - Verify correct scope (`mcp.access`) inclusion

-   **400 Bad Request Error**:
    - Verify Content-Type is `application/x-www-form-urlencoded`
    - Check required parameters (`grant_type`, `client_id`, `client_secret`) inclusion

### 7.3. Security Feature Debugging

-   **Check Security Audit Logs**:
    ```bash
    # Real-time security log monitoring
    tail -f oauth2-demo/logs/security_audit.log
    
    # Check logs for specific time period
    grep "2025-01-06T12" oauth2-demo/logs/security_audit.log
    
    # Check PII detection events only
    grep "contains_pii.*true" oauth2-demo/logs/security_audit.log
    ```

-   **PII Detection Issues**:
    ```bash
    # Check PII pattern file
    cat oauth2-demo/security/pii_patterns.json
    
    # Test PII detection
    python -c "
    from oauth2_demo.security.security_common import get_pii_detector
    detector = get_pii_detector()
    print(detector.scan_text('Test email: test@example.com'))
    "
    ```

-   **Encryption Key Issues**:
    ```bash
    # Check encryption key directory
    ls -la oauth2-demo/keys/
    ls -la oauth2-demo/tests/keys/
    
    # Check key permissions
    chmod 600 oauth2-demo/keys/encryption.key
    ```

### 7.4. MCP Tool Connection Issues

-   **MCP Tool Not Responding**:
    ```bash
    # Test MCP tool directly
    docker exec -i mcp-python-server-docker uv run /workspace/oauth2-demo/core/oauth2_mcp_tools.py
    
    # Restart MCP server in Cursor
    # Ctrl+Shift+P → "MCP: Restart Server"
    ```

-   **Virtual Environment Issues**:
    ```bash
    # Check virtual environment
    source .venv/bin/activate
    which python
    
    # Reinstall dependencies
    uv pip install -r requirements.txt
    ```

### 7.5. System-wide Status Check with Integration Tests

```bash
# Complete system status check script
./scripts/health_check.sh

# Or manual sequential testing
source .venv/bin/activate
python oauth2-demo/tests/test_oauth2_demo.py
python oauth2-demo/tests/test_mcp_tools_direct.py
python oauth2-demo/tests/test_mcp_integration.py
```

This multi-layered security architecture provides a complete security solution with **OAuth2 authentication** + **PII protection** + **data encryption** + **audit tracking**.

------------------ 