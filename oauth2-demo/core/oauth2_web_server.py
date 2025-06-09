"""
OAuth2 웹 서버

FastAPI 기반 OAuth2 Authorization Server + Resource Server
HTTP API로 토큰 발급 및 보호된 리소스 제공
"""

from datetime import datetime
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security, status, Form
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fastmcp import FastMCP # FastMCP 임포트 추가

from oauth2_common import (
    authenticate_client,
    create_jwt_token,
    verify_jwt_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY
)

# FastAPI 앱 초기화
app = FastAPI(
    title="MCP OAuth2 웹 서버",
    description="OAuth2 Authorization Server + Resource Server",
    version="1.0.0"
)

# 보안 스킴
security = HTTPBearer(auto_error=False)

# MCP 인스턴스 생성 (OAuth2 도구용)
# 이 FastMCP 인스턴스는 OAuth2 웹 서버 내에서 자체적으로 도구들을 관리합니다.
# 메인 MCP 서버가 이 인스턴스에 등록된 도구들을 원격으로 가져올 수 있도록 합니다.
mcp_oauth2_tools = FastMCP("OAuth2 MCP Tools (Docker exec)")

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

# MCP 도구 정의 (OAuth2 인증 필요)
@mcp_oauth2_tools.tool
async def get_oauth2_token_endpoint(current_client: str = Depends(get_current_client)) -> str:
    """OAuth2 토큰 엔드포인트 URL을 반환합니다. (OAuth2 인증 필요)"""
    return "http://localhost:8081/oauth2/token"

@mcp_oauth2_tools.tool
async def get_oauth2_hello_endpoint(current_client: str = Depends(get_current_client)) -> str:
    """보호된 Hello 엔드포인트 URL을 반환합니다. (OAuth2 인증 필요)"""
    return "http://localhost:8081/hello"

@mcp_oauth2_tools.tool
async def get_oauth2_jwks_uri(current_client: str = Depends(get_current_client)) -> str:
    """JSON Web Key Set (JWKS) URI를 반환합니다. (OAuth2 인증 필요)"""
    return "http://localhost:8081/.well-known/jwks.json"

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
    """보호된 Hello 엔드포인트"""
    return HelloResponse(
        message="MCP OAuth2 웹 서버에서 안녕하세요!",
        authenticated_client=current_client,
        timestamp=datetime.utcnow().isoformat()
    )

# 루트 엔드포인트 (보호됨)
@app.get("/")
async def root(current_client: str = Depends(get_current_client)):
    """루트 엔드포인트 (보호됨)"""
    return {
        "message": "MCP OAuth2 웹 서버",
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
    """OpenID Connect Discovery 엔드포인트"""
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

# JWKS 엔드포인트
@app.get("/.well-known/jwks.json")
async def jwks():
    """JSON Web Key Set (JWKS) 엔드포인트"""
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
    """OAuth2 웹 서버 실행"""
    print("🔐 MCP OAuth2 웹 서버를 시작합니다...")
    print("📍 서버 주소: http://localhost:8081")
    print("🔑 토큰 엔드포인트: http://localhost:8081/oauth2/token")
    print("👋 보호된 엔드포인트: http://localhost:8081/hello")
    print("💡 참고: OAuth2 MCP 도구는 별도의 MCP 서버로 실행됩니다")
    
    uvicorn.run(app, host="0.0.0.0", port=8081)

if __name__ == "__main__":
    run_server() 