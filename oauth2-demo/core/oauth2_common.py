"""
OAuth2 공통 로직 모듈

JWT 토큰 생성/검증, 클라이언트 인증 등 공통 기능을 제공합니다.
"""

import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

import jwt
from fastapi import HTTPException, status

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "mcp-oauth2-demo-secret-key-2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 클라이언트 설정
CLIENT_CREDENTIALS = {
    "mcp-client": "secret"  # 실제 운영에서는 안전한 시크릿 사용
}

def create_jwt_token(data: Dict[str, Any], expires_delta: timedelta = None) -> str:
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

def create_test_token_data(client_id: str = "mcp-client") -> Dict[str, Any]:
    """
    테스트용 토큰 데이터 생성
    
    Args:
        client_id: 클라이언트 ID
        
    Returns:
        토큰 데이터와 사용 예제
    """
    token_data = {
        "sub": client_id,
        "aud": "mcp-client",
        "scope": "mcp.access",
        "client_id": client_id
    }
    
    access_token = create_jwt_token(token_data)
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "scope": "mcp.access",
        "usage_example": f"curl -H 'Authorization: Bearer {access_token}' http://localhost:8081/hello"
    } 