"""
MCP OAuth2 데모 서버

이 프로젝트는 Microsoft의 MCP for beginners OAuth2 데모의 Python 구현입니다.
FastAPI 기반으로 OAuth2 Authorization Server와 Resource Server를 모두 제공합니다.

주요 기능:
- OAuth2 client_credentials 플로우
- JWT 토큰 발급 및 검증
- 보호된 MCP 엔드포인트
- FastMCP 인증 시스템 통합

출처: https://github.com/microsoft/mcp-for-beginners/tree/main/05-AdvancedTopics/mcp-oauth2-demo
"""

import asyncio
import json
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Security, status, Form
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from fastmcp import FastMCP
from pydantic import BaseModel
import uvicorn

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "mcp-oauth2-demo-secret-key-2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 클라이언트 설정
CLIENT_CREDENTIALS = {
    "mcp-client": "secret"  # 실제 운영에서는 안전한 시크릿 사용
}

# FastAPI 앱 초기화
app = FastAPI(
    title="MCP OAuth2 데모",
    description="Microsoft MCP for beginners OAuth2 데모의 Python 구현",
    version="1.0.0"
)

# 보안 스킴
security = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="oauth2/token")

# FastMCP 인스턴스
mcp = FastMCP("MCP OAuth2 데모")

class TokenRequest(BaseModel):
    """OAuth2 토큰 요청 모델"""
    grant_type: str
    scope: Optional[str] = None

class TokenResponse(BaseModel):
    """OAuth2 토큰 응답 모델"""
    access_token: str
    token_type: str
    expires_in: int
    scope: Optional[str] = None

class HelloResponse(BaseModel):
    """Hello 엔드포인트 응답 모델"""
    message: str
    authenticated_client: str
    timestamp: str

def create_jwt_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    JWT 토큰 생성
    
    Args:
        data: 토큰에 포함할 데이터
        expires_delta: 토큰 만료 시간
        
    Returns:
        생성된 JWT 토큰
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4())  # JWT ID
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """
    JWT 토큰 검증
    
    Args:
        token: 검증할 JWT 토큰
        
    Returns:
        토큰에 포함된 데이터
        
    Raises:
        HTTPException: 토큰이 유효하지 않은 경우
    """
    try:
        # audience 검증 비활성화 (데모 목적)
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],
            options={"verify_aud": False}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰이 만료되었습니다",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 토큰입니다",
            headers={"WWW-Authenticate": "Bearer"},
        )

def authenticate_client(client_id: str, client_secret: str) -> bool:
    """
    OAuth2 클라이언트 인증
    
    Args:
        client_id: 클라이언트 ID
        client_secret: 클라이언트 시크릿
        
    Returns:
        인증 성공 여부
    """
    return CLIENT_CREDENTIALS.get(client_id) == client_secret

async def get_current_client(credentials: Optional[HTTPAuthorizationCredentials] = Security(security)) -> str:
    """
    현재 인증된 클라이언트 정보 가져오기
    
    Args:
        credentials: HTTP Bearer 토큰
        
    Returns:
        클라이언트 ID
        
    Raises:
        HTTPException: 인증 실패 시
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="인증이 필요합니다",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    client_id: str = payload.get("sub")
    if client_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="토큰에서 클라이언트 정보를 찾을 수 없습니다",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 스코프 검증
    scope: str = payload.get("scope", "")
    if "mcp.access" not in scope:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MCP 접근 권한이 없습니다",
        )
    
    return client_id

# OAuth2 토큰 엔드포인트
@app.post("/oauth2/token", response_model=TokenResponse)
async def get_token(
    grant_type: str = Form(),
    scope: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None)
):
    """
    OAuth2 토큰 발급 엔드포인트
    
    client_credentials 그랜트 타입을 지원합니다.
    
    Args:
        grant_type: 그랜트 타입 (client_credentials만 지원)
        scope: 요청된 스코프
        client_id: 클라이언트 ID
        client_secret: 클라이언트 시크릿
        
    Returns:
        OAuth2 토큰 응답
        
    Raises:
        HTTPException: 인증 실패 또는 지원하지 않는 그랜트 타입
    """
    # 그랜트 타입 검증
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="지원하지 않는 그랜트 타입입니다. client_credentials만 지원합니다."
        )
    
    # 클라이언트 인증
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_id와 client_secret이 필요합니다"
        )
    
    if not authenticate_client(client_id, client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 클라이언트 자격 증명입니다"
        )
    
    # 스코프 검증 및 기본값 설정
    if not scope:
        scope = "mcp.access"
    
    if "mcp.access" not in scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mcp.access 스코프가 필요합니다"
        )
    
    # JWT 토큰 생성
    token_data = {
        "sub": client_id,
        "aud": "mcp-client",
        "scope": scope,
        "client_id": client_id
    }
    
    access_token = create_jwt_token(token_data)
    
    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        scope=scope
    )

# 보호된 Hello 엔드포인트
@app.get("/hello", response_model=HelloResponse)
async def hello(current_client: str = Depends(get_current_client)):
    """
    보호된 Hello 엔드포인트
    
    유효한 OAuth2 토큰이 필요합니다.
    
    Args:
        current_client: 현재 인증된 클라이언트 ID
        
    Returns:
        인사 메시지와 클라이언트 정보
    """
    return HelloResponse(
        message="MCP OAuth2 데모에서 안녕하세요!",
        authenticated_client=current_client,
        timestamp=datetime.utcnow().isoformat()
    )

# 루트 엔드포인트 (보호됨)
@app.get("/")
async def root(current_client: str = Depends(get_current_client)):
    """
    루트 엔드포인트 (보호됨)
    
    Args:
        current_client: 현재 인증된 클라이언트 ID
        
    Returns:
        서버 정보
    """
    return {
        "message": "MCP OAuth2 데모 서버",
        "client": current_client,
        "endpoints": [
            "/oauth2/token",
            "/hello",
            "/.well-known/openid-configuration"
        ]
    }

# OpenID Connect Discovery 엔드포인트
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """
    OpenID Connect Discovery 엔드포인트
    
    OAuth2/OpenID Connect 클라이언트가 서버 설정을 자동으로 발견할 수 있게 해줍니다.
    
    Returns:
        OpenID Connect 설정 정보
    """
    return {
        "issuer": "http://localhost:8081",
        "authorization_endpoint": "http://localhost:8081/oauth2/authorize",
        "token_endpoint": "http://localhost:8081/oauth2/token",
        "jwks_uri": "http://localhost:8081/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["mcp.access"],
        "claims_supported": ["sub", "aud", "iss", "exp", "iat", "scope"]
    }

# JWKS 엔드포인트 (JWT 서명 키 정보)
@app.get("/.well-known/jwks.json")
async def jwks():
    """
    JSON Web Key Set (JWKS) 엔드포인트
    
    JWT 토큰 검증에 사용되는 공개 키 정보를 제공합니다.
    실제 운영에서는 RSA 키 페어를 사용해야 합니다.
    
    Returns:
        JWKS 정보
    """
    # 데모 목적으로 간단한 JWKS 반환
    # 실제 운영에서는 RSA 공개 키를 제공해야 함
    return {
        "keys": [
            {
                "kty": "oct",
                "kid": "demo-key",
                "use": "sig",
                "alg": "HS256",
                "k": SECRET_KEY  # 실제로는 공개 키만 노출해야 함
            }
        ]
    }

# FastMCP 도구 등록
@mcp.tool()
def get_server_status() -> str:
    """
    MCP OAuth2 데모 서버의 현재 상태를 가져옵니다.
    
    Returns:
        서버 상태 정보
    """
    return json.dumps({
        "status": "실행 중",
        "server": "MCP OAuth2 데모",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "token": "/oauth2/token",
            "hello": "/hello",
            "discovery": "/.well-known/openid-configuration"
        }
    }, ensure_ascii=False, indent=2)

@mcp.tool()
def create_test_token(client_id: str = "mcp-client") -> str:
    """
    테스트용 OAuth2 토큰을 생성합니다.
    
    Args:
        client_id: 클라이언트 ID (기본값: mcp-client)
        
    Returns:
        생성된 테스트 토큰 정보
    """
    token_data = {
        "sub": client_id,
        "aud": "mcp-client",
        "scope": "mcp.access",
        "client_id": client_id
    }
    
    access_token = create_jwt_token(token_data)
    
    return json.dumps({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "scope": "mcp.access",
        "usage_example": f"curl -H 'Authorization: Bearer {access_token}' http://localhost:8081/hello"
    }, ensure_ascii=False, indent=2)

# 예외 처리
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "요청된 리소스를 찾을 수 없습니다"}
    )

@app.exception_handler(500)
async def server_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "서버 내부 오류가 발생했습니다"}
    )

def run_server():
    """OAuth2 데모 서버 실행"""
    print("🔐 MCP OAuth2 데모 서버를 시작합니다...")
    print("📍 서버 주소: http://localhost:8081")
    print("🔑 토큰 엔드포인트: http://localhost:8081/oauth2/token")
    print("👋 보호된 엔드포인트: http://localhost:8081/hello")
    print("\n📖 사용 예제:")
    print("1. 토큰 획득:")
    print("   curl -u mcp-client:secret -d grant_type=client_credentials http://localhost:8081/oauth2/token")
    print("2. 보호된 리소스 접근:")
    print("   curl -H 'Authorization: Bearer <토큰>' http://localhost:8081/hello")
    
    uvicorn.run(app, host="0.0.0.0", port=8081)

if __name__ == "__main__":
    run_server() 