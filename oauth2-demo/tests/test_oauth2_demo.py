#!/usr/bin/env python3
"""
MCP OAuth2 데모 테스트 스크립트

이 스크립트는 OAuth2 데모 서버의 기능을 테스트합니다.
"""

import asyncio
import json
import time
from typing import Dict, Optional

import httpx


class OAuth2DemoTester:
    """OAuth2 데모 서버 테스트 클래스"""
    
    def __init__(self, base_url: str = "http://localhost:8081"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def close(self):
        """HTTP 클라이언트 종료"""
        await self.client.aclose()
    
    async def test_server_health(self) -> bool:
        """서버 상태 확인"""
        try:
            response = await self.client.get(
                f"{self.base_url}/.well-known/openid-configuration"
            )
            return response.status_code == 200
        except Exception as e:
            print(f"❌ 서버 상태 확인 실패: {e}")
            return False
    
    async def get_token(
        self, 
        client_id: str = "mcp-client", 
        client_secret: str = "secret"
    ) -> Optional[Dict]:
        """OAuth2 토큰 획득"""
        try:
            # Form 데이터로 토큰 요청
            data = {
                "grant_type": "client_credentials",
                "scope": "mcp.access",
                "client_id": client_id,
                "client_secret": client_secret
            }
            
            response = await self.client.post(
                f"{self.base_url}/oauth2/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                token_data = response.json()
                print(f"✅ 토큰 획득 성공:")
                print(f"   - 토큰 타입: {token_data.get('token_type')}")
                print(f"   - 만료 시간: {token_data.get('expires_in')}초")
                print(f"   - 스코프: {token_data.get('scope')}")
                return token_data
            else:
                print(f"❌ 토큰 획득 실패: {response.status_code}")
                print(f"   응답: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ 토큰 요청 중 오류: {e}")
            return None
    
    async def test_protected_endpoint(self, access_token: str) -> bool:
        """보호된 엔드포인트 테스트"""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            
            # Hello 엔드포인트 테스트
            response = await self.client.get(
                f"{self.base_url}/hello",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Hello 엔드포인트 테스트 성공:")
                print(f"   - 메시지: {data.get('message')}")
                print(f"   - 인증된 클라이언트: {data.get('authenticated_client')}")
                print(f"   - 타임스탬프: {data.get('timestamp')}")
                return True
            else:
                print(f"❌ Hello 엔드포인트 테스트 실패: {response.status_code}")
                print(f"   응답: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ 보호된 엔드포인트 테스트 중 오류: {e}")
            return False
    
    async def test_root_endpoint(self, access_token: str) -> bool:
        """루트 엔드포인트 테스트"""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            
            response = await self.client.get(
                f"{self.base_url}/",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ 루트 엔드포인트 테스트 성공:")
                print(f"   - 메시지: {data.get('message')}")
                print(f"   - 클라이언트: {data.get('client')}")
                print(f"   - 엔드포인트: {data.get('endpoints')}")
                return True
            else:
                print(f"❌ 루트 엔드포인트 테스트 실패: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 루트 엔드포인트 테스트 중 오류: {e}")
            return False
    
    async def test_unauthorized_access(self) -> bool:
        """인증 없는 접근 테스트 (실패해야 함)"""
        try:
            # 토큰 없이 보호된 엔드포인트 접근
            response = await self.client.get(f"{self.base_url}/hello")
            
            if response.status_code == 401:
                print("✅ 인증 없는 접근이 올바르게 차단됨")
                return True
            else:
                print(f"❌ 인증 없는 접근이 차단되지 않음: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 인증 없는 접근 테스트 중 오류: {e}")
            return False
    
    async def test_invalid_token(self) -> bool:
        """잘못된 토큰 테스트 (실패해야 함)"""
        try:
            headers = {"Authorization": "Bearer invalid_token"}
            
            response = await self.client.get(
                f"{self.base_url}/hello",
                headers=headers
            )
            
            if response.status_code == 401:
                print("✅ 잘못된 토큰이 올바르게 거부됨")
                return True
            else:
                print(f"❌ 잘못된 토큰이 거부되지 않음: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ 잘못된 토큰 테스트 중 오류: {e}")
            return False
    
    async def test_discovery_endpoint(self) -> bool:
        """OpenID Connect Discovery 엔드포인트 테스트"""
        try:
            response = await self.client.get(
                f"{self.base_url}/.well-known/openid-configuration"
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ OpenID Connect Discovery 엔드포인트 테스트 성공:")
                print(f"   - Issuer: {data.get('issuer')}")
                print(f"   - Token Endpoint: {data.get('token_endpoint')}")
                print(f"   - JWKS URI: {data.get('jwks_uri')}")
                return True
            else:
                print(f"❌ Discovery 엔드포인트 테스트 실패: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Discovery 엔드포인트 테스트 중 오류: {e}")
            return False
    
    async def test_jwks_endpoint(self) -> bool:
        """JWKS 엔드포인트 테스트"""
        try:
            response = await self.client.get(
                f"{self.base_url}/.well-known/jwks.json"
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✅ JWKS 엔드포인트 테스트 성공:")
                print(f"   - 키 개수: {len(data.get('keys', []))}")
                return True
            else:
                print(f"❌ JWKS 엔드포인트 테스트 실패: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ JWKS 엔드포인트 테스트 중 오류: {e}")
            return False
    
    async def run_all_tests(self) -> bool:
        """모든 테스트 실행"""
        print("🧪 MCP OAuth2 데모 서버 테스트를 시작합니다...\n")
        
        tests_passed = 0
        total_tests = 7
        
        # 1. 서버 상태 확인
        print("1️⃣ 서버 상태 확인...")
        if await self.test_server_health():
            tests_passed += 1
        else:
            print("❌ 서버가 실행되지 않았거나 접근할 수 없습니다.")
            return False
        
        print()
        
        # 2. Discovery 엔드포인트 테스트
        print("2️⃣ OpenID Connect Discovery 엔드포인트 테스트...")
        if await self.test_discovery_endpoint():
            tests_passed += 1
        
        print()
        
        # 3. JWKS 엔드포인트 테스트
        print("3️⃣ JWKS 엔드포인트 테스트...")
        if await self.test_jwks_endpoint():
            tests_passed += 1
        
        print()
        
        # 4. 토큰 획득 테스트
        print("4️⃣ OAuth2 토큰 획득 테스트...")
        token_data = await self.get_token()
        if token_data:
            access_token = token_data.get("access_token")
            tests_passed += 1
        else:
            print("❌ 토큰 획득에 실패하여 나머지 테스트를 건너뜁니다.")
            return False
        
        print()
        
        # 5. 보호된 엔드포인트 테스트
        print("5️⃣ 보호된 엔드포인트 접근 테스트...")
        if await self.test_protected_endpoint(access_token):
            tests_passed += 1
        
        print()
        
        # 6. 인증 없는 접근 테스트
        print("6️⃣ 인증 없는 접근 차단 테스트...")
        if await self.test_unauthorized_access():
            tests_passed += 1
        
        print()
        
        # 7. 잘못된 토큰 테스트
        print("7️⃣ 잘못된 토큰 거부 테스트...")
        if await self.test_invalid_token():
            tests_passed += 1
        
        print()
        
        # 결과 출력
        print("=" * 50)
        print(f"📊 테스트 결과: {tests_passed}/{total_tests} 통과")
        
        if tests_passed == total_tests:
            print("🎉 모든 테스트를 통과했습니다!")
            return True
        else:
            print(f"⚠️  {total_tests - tests_passed}개 테스트가 실패했습니다.")
            return False


async def main():
    """메인 함수"""
    tester = OAuth2DemoTester()
    
    try:
        # 서버 시작 대기
        print("⏳ 서버 시작을 기다리는 중...")
        await asyncio.sleep(2)
        
        # 모든 테스트 실행
        success = await tester.run_all_tests()
        
        if success:
            print("\n🔍 추가 테스트 명령어:")
            print("# 1. 토큰 획득:")
            print("curl -X POST http://localhost:8081/oauth2/token \\")
            print("  -H 'Content-Type: application/x-www-form-urlencoded' \\")
            print("  -d 'grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access'")
            print()
            print("# 2. 보호된 리소스 접근:")
            print("curl -H 'Authorization: Bearer <YOUR_TOKEN>' http://localhost:8081/hello")
            
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main()) 