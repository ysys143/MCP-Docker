# 보안 모범 사례

보안은 특히 기업 환경에서 MCP 구현에 매우 중요합니다. 도구와 데이터가 무단 접근, 데이터 유출 및 기타 보안 위협으로부터 보호되도록 하는 것이 중요합니다.

## 소개

이 강의에서는 MCP 구현을 위한 보안 모범 사례를 살펴보겠습니다. 인증 및 권한 부여, 데이터 보호, 안전한 도구 실행, 데이터 개인정보 보호 규정 준수에 대해 다룰 것입니다.

## 학습 목표

이 강의를 마치면 다음을 할 수 있게 됩니다:

- MCP 서버를 위한 안전한 인증 및 권한 부여 메커니즘을 구현합니다.
- 암호화 및 안전한 저장을 사용하여 민감한 데이터를 보호합니다.
- 적절한 접근 제어를 통해 도구의 안전한 실행을 보장합니다.
- 데이터 보호 및 개인정보 보호 준수를 위한 모범 사례를 적용합니다.

## 인증 및 권한 부여

인증과 권한 부여는 MCP 서버를 보호하는 데 필수적입니다. 인증은 "당신은 누구입니까?"라는 질문에 답하고, 권한 부여는 "당신은 무엇을 할 수 있습니까?"라는 질문에 답합니다.

Python MCP 서버에서 안전한 인증 및 권한 부여를 구현하는 방법의 예시를 살펴보겠습니다.

### FastMCP를 사용한 Python JWT 인증

JWT 인증과 역할 기반 접근 제어를 사용하여 안전한 MCP 서버를 Python으로 구현할 수 있습니다. 핵심 개념은 다음과 같습니다:

- **JWT 인증**: 안전한 API 접근을 위해 JSON 웹 토큰(JWT)을 사용합니다. JWT는 디지털 서명으로 검증되고 신뢰할 수 있는 JSON 객체로 당사자 간에 정보를 안전하게 전송하는 표준입니다.
- **역할 기반 접근 제어**: 사용자 권한에 따라 특정 도구에 대한 접근을 제어하는 역할을 사용합니다.
- **보안 데코레이터**: Python 데코레이터를 사용하여 도구 실행에 대한 접근 제어를 강화합니다.
- **권한 부여 정책**: 사용자 역할과 클레임에 따라 특정 도구에 대한 접근을 제어하는 정책을 정의합니다.

```python
import jwt
import json
import asyncio
from datetime import datetime, timedelta
from functools import wraps
from fastmcp import FastMCP
from typing import Dict, List, Optional

class User:
    def __init__(self, user_id: str, username: str, roles: List[str]):
        self.user_id = user_id
        self.username = username
        self.roles = roles

class AuthenticationService:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.users_db = {
            "admin": User("1", "admin", ["admin", "user"]),
            "user": User("2", "user", ["user"]),
            "guest": User("3", "guest", ["guest"])
        }
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """인증된 사용자 반환"""
        # 실제 구현에서는 데이터베이스에서 사용자 확인 및 비밀번호 해시 검증
        if username in self.users_db:
            return self.users_db[username]
        return None
    
    def generate_token(self, user: User) -> str:
        """JWT 토큰 생성"""
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "roles": user.roles,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[User]:
        """JWT 토큰 검증 및 사용자 정보 반환"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return User(
                user_id=payload["user_id"],
                username=payload["username"],
                roles=payload["roles"]
            )
        except jwt.ExpiredSignatureError:
            print("토큰이 만료되었습니다")
            return None
        except jwt.InvalidTokenError:
            print("유효하지 않은 토큰입니다")
            return None

class SecureMCPServer:
    def __init__(self, secret_key: str):
        self.auth_service = AuthenticationService(secret_key)
        self.mcp = FastMCP("Secure MCP Server")
        self.setup_tools()
    
    def require_role(self, required_roles: List[str]):
        """역할 기반 접근 제어 데코레이터"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # MCP 컨텍스트에서 토큰 추출 (실제 구현에서는 MCP 메시지에서 추출)
                token = kwargs.get('auth_token')
                if not token:
                    raise PermissionError("인증 토큰이 필요합니다")
                
                user = self.auth_service.verify_token(token)
                if not user:
                    raise PermissionError("유효하지 않은 토큰입니다")
                
                # 사용자 역할 확인
                if not any(role in user.roles for role in required_roles):
                    raise PermissionError(f"필요한 역할: {required_roles}, 사용자 역할: {user.roles}")
                
                # 사용자 정보를 함수에 전달
                kwargs['current_user'] = user
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def setup_tools(self):
        """보안이 적용된 도구들 설정"""
        
        @self.mcp.tool()
        @self.require_role(["user", "admin"])
        async def get_weather(city: str, auth_token: str = None, current_user: User = None) -> dict:
            """기본 사용자가 접근 가능한 날씨 조회 도구"""
            print(f"사용자 {current_user.username}이 {city} 날씨를 조회합니다")
            # 날씨 정보 반환
            return {
                "city": city,
                "temperature": 25,
                "condition": "맑음",
                "user": current_user.username
            }
        
        @self.mcp.tool()
        @self.require_role(["admin"])
        async def admin_system_status(auth_token: str = None, current_user: User = None) -> dict:
            """관리자만 접근 가능한 시스템 상태 조회"""
            print(f"관리자 {current_user.username}이 시스템 상태를 조회합니다")
            return {
                "status": "정상",
                "users_online": 42,
                "admin": current_user.username
            }
        
        @self.mcp.tool()
        @self.require_role(["admin"])
        async def delete_user_data(user_id: str, auth_token: str = None, current_user: User = None) -> dict:
            """관리자만 접근 가능한 민감한 데이터 삭제"""
            print(f"관리자 {current_user.username}이 사용자 {user_id} 데이터를 삭제합니다")
            # 실제로는 데이터베이스에서 삭제
            return {
                "result": "사용자 데이터가 삭제되었습니다",
                "deleted_user": user_id,
                "admin": current_user.username
            }

# 보안 인터셉터 구현
class SecurityInterceptor:
    def __init__(self, auth_service: AuthenticationService):
        self.auth_service = auth_service
    
    async def before_tool_execution(self, tool_name: str, parameters: dict) -> dict:
        """도구 실행 전 보안 검사"""
        print(f"보안 검사: 도구 '{tool_name}' 실행 요청")
        
        # 민감한 도구에 대한 추가 검증
        if tool_name in ["delete_user_data", "admin_system_status"]:
            # 관리자 권한 재확인
            token = parameters.get('auth_token')
            user = self.auth_service.verify_token(token)
            if not user or "admin" not in user.roles:
                raise PermissionError("관리자 권한이 필요한 도구입니다")
        
        # 감사 로그
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] 도구 실행: {tool_name}")
        
        return parameters

# 사용 예시
if __name__ == "__main__":
    # 보안 MCP 서버 초기화
    secret_key = "your-secret-key-here"  # 실제로는 환경변수에서 가져와야 함
    secure_server = SecureMCPServer(secret_key)
    
    # 토큰 생성 예시
    admin_user = secure_server.auth_service.authenticate_user("admin", "password")
    if admin_user:
        admin_token = secure_server.auth_service.generate_token(admin_user)
        print(f"관리자 토큰: {admin_token}")
    
    # MCP 서버 실행
    secure_server.mcp.run()
```

### Python OAuth2 Integration with MCP

OAuth2를 사용한 더 고급 인증 시스템도 구현할 수 있습니다:

```python
import httpx
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastmcp import FastMCP

class OAuth2AuthService:
    def __init__(self, oauth_provider_url: str, client_id: str, client_secret: str):
        self.oauth_provider_url = oauth_provider_url
        self.client_id = client_id
        self.client_secret = client_secret
    
    async def verify_oauth_token(self, token: str) -> Optional[Dict]:
        """OAuth2 토큰을 검증하고 사용자 정보 반환"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.oauth_provider_url}/userinfo",
                headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code == 200:
                return response.json()
        return None

class OAuth2SecureMCP:
    def __init__(self, oauth_service: OAuth2AuthService):
        self.oauth_service = oauth_service
        self.mcp = FastMCP("OAuth2 Secure MCP Server")
        self.security = HTTPBearer()
        self.setup_tools()
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials):
        """OAuth2 토큰에서 현재 사용자 정보 추출"""
        user_info = await self.oauth_service.verify_oauth_token(credentials.credentials)
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="유효하지 않은 토큰"
            )
        return user_info
    
    def setup_tools(self):
        @self.mcp.tool()
        async def secure_data_access(query: str, auth_token: str) -> dict:
            """OAuth2로 보호된 데이터 접근"""
            # 토큰 검증
            user_info = await self.oauth_service.verify_oauth_token(auth_token)
            if not user_info:
                raise PermissionError("유효하지 않은 OAuth2 토큰")
            
            # 사용자별 데이터 접근
            return {
                "data": f"사용자 {user_info['name']}의 보안 데이터",
                "query": query,
                "user_id": user_info['sub']
            }
```

위 코드에서 우리는 다음을 구현했습니다:

- **JWT 인증**: 토큰 생성 및 검증을 포함한 완전한 JWT 인증 시스템을 구현했습니다.
- **역할 기반 접근 제어**: 다양한 도구에 대한 역할 기반 접근을 강화하는 데코레이터를 생성했습니다.
- **보안 인터셉터**: 도구 실행 전 추가 검사를 수행하는 보안 인터셉터를 구현했습니다.
- **OAuth2 통합**: 더 고급 시나리오를 위한 OAuth2 인증 통합 방법을 보여주었습니다.
- **감사 로깅**: 도구 사용 및 보안 이벤트를 추적하는 로깅 기능을 추가했습니다.

## 데이터 보호 및 개인정보 보호

데이터 보호는 민감한 정보가 안전하게 처리되도록 하는 데 중요합니다. 여기에는 개인 식별 정보(PII), 금융 데이터 및 기타 민감한 정보를 무단 접근 및 유출로부터 보호하는 것이 포함됩니다.

### Python 데이터 보호 예시

암호화와 PII 탐지를 사용하여 Python에서 데이터 보호를 구현하는 방법의 예시를 살펴보겠습니다.

```python
from mcp_server import McpServer
from mcp_tools import Tool, ToolRequest, ToolResponse
from cryptography.fernet import Fernet
import os
import json
from functools import wraps

# PII 탐지기 - 민감한 정보 식별 및 보호
class PiiDetector:
    def __init__(self):
        # 다양한 PII 유형에 대한 패턴 로드
        with open("pii_patterns.json", "r") as f:
            self.patterns = json.load(f)
    
    def scan_text(self, text):
        """텍스트에서 PII를 스캔하고 탐지된 PII 유형을 반환"""
        detected_pii = []
        # 정규식 또는 ML 모델을 사용하여 PII 탐지 구현
        return detected_pii
    
    def scan_parameters(self, parameters):
        """요청 매개변수에서 PII 스캔"""
        detected_pii = []
        for key, value in parameters.items():
            if isinstance(value, str):
                pii_in_value = self.scan_text(value)
                if pii_in_value:
                    detected_pii.append((key, pii_in_value))
        return detected_pii

# 민감한 데이터 보호를 위한 암호화 서비스
class EncryptionService:
    def __init__(self, key_path=None):
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            if key_path:
                with open(key_path, "wb") as key_file:
                    key_file.write(self.key)
        
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data):
        """데이터 암호화"""
        if isinstance(data, str):
            return self.cipher.encrypt(data.encode()).decode()
        else:
            return self.cipher.encrypt(json.dumps(data).encode()).decode()
    
    def decrypt(self, encrypted_data):
        """데이터 복호화"""
        if encrypted_data is None:
            return None
        
        decrypted = self.cipher.decrypt(encrypted_data.encode())
        try:
            return json.loads(decrypted)
        except:
            return decrypted.decode()

# 도구를 위한 보안 데코레이터
def secure_tool(requires_encryption=False, log_access=True):
    def decorator(cls):
        original_execute = cls.execute_async if hasattr(cls, 'execute_async') else cls.execute
        
        @wraps(original_execute)
        async def secure_execute(self, request):
            # 요청에서 PII 확인
            pii_detector = PiiDetector()
            pii_found = pii_detector.scan_parameters(request.parameters)
            
            # 필요시 접근 로그 기록
            if log_access:
                tool_name = self.get_name()
                user_id = request.context.get("user_id", "anonymous")
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "tool": tool_name,
                    "user": user_id,
                    "contains_pii": bool(pii_found),
                    "parameters": {k: "***" for k in request.parameters.keys()}  # 실제 값은 로그에 기록하지 않음
                }
                logging.info(f"도구 접근: {json.dumps(log_entry)}")
            
            # 탐지된 PII 처리
            if pii_found:
                # 민감한 데이터를 암호화하거나 요청을 거부
                if requires_encryption:
                    encryption_service = EncryptionService("keys/tool_key.key")
                    for param_name, pii_types in pii_found:
                        # 민감한 매개변수 암호화
                        request.parameters[param_name] = encryption_service.encrypt(
                            request.parameters[param_name]
                        )
                else:
                    # 암호화를 사용할 수 없지만 PII가 발견된 경우 요청을 거부할 수 있음
                    raise ToolExecutionException(
                        "요청에 안전하게 처리할 수 없는 민감한 데이터가 포함되어 있습니다"
                    )
            
            # 원래 메서드 실행
            return await original_execute(self, request)
        
        # execute 메서드 교체
        if hasattr(cls, 'execute_async'):
            cls.execute_async = secure_execute
        else:
            cls.execute = secure_execute
        return cls
    
    return decorator

# 데코레이터를 사용한 보안 도구의 예시
@secure_tool(requires_encryption=True, log_access=True)
class SecureCustomerDataTool(Tool):
    def get_name(self):
        return "customerData"
    
    def get_description(self):
        return "고객 데이터에 안전하게 접근합니다"
    
    def get_schema(self):
        # 스키마 정의
        return {}
    
    async def execute_async(self, request):
        # 고객 데이터에 안전하게 접근하는 구현
        # 데코레이터를 사용했으므로 PII가 이미 탐지되고 암호화됨
        return ToolResponse(result={"status": "success"})
```

위 코드에서 우리는 다음을 구현했습니다:

- 개인 식별 정보(PII)에 대해 텍스트와 매개변수를 스캔하는 `PiiDetector` 클래스를 구현했습니다.
- `cryptography` 라이브러리를 사용하여 민감한 데이터의 암호화 및 복호화를 처리하는 `EncryptionService` 클래스를 생성했습니다.
- PII 확인, 접근 로그 기록, 필요시 민감한 데이터 암호화를 위해 도구 실행을 래핑하는 `secure_tool` 데코레이터를 정의했습니다.
- 샘플 도구(`SecureCustomerDataTool`)에 `secure_tool` 데코레이터를 적용하여 민감한 데이터를 안전하게 처리하도록 했습니다.

## 다음 단계

- [웹 검색](../web-search-mcp/README.md)