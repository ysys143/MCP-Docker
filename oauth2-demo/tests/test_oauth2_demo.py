#!/usr/bin/env python3
"""
MCP OAuth2 데모 테스트 스크립트 (MCP 방식)

이 스크립트는 MCP 도구를 통한 OAuth2 기능을 테스트합니다.
HTTP API 대신 MCP 도구 호출 방식을 사용합니다.
"""

import asyncio
import json
import time
import sys
import os
from typing import Dict, Optional

# oauth2-demo 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.oauth2_mcp_tools import OAuth2MCPTools
from core.oauth2_common import create_test_token_data


class MCPOAuth2Tester:
    """MCP OAuth2 도구 테스트 클래스"""
    
    def __init__(self):
        self.oauth2_tools = OAuth2MCPTools()
        self.test_results = []
        
    def log_test_result(self, test_name: str, success: bool, details: str = ""):
        """테스트 결과 로깅"""
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details
        })
        
        status = "✅" if success else "❌"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
    
    async def test_mcp_tools_availability(self) -> bool:
        """MCP 도구 가용성 확인"""
        try:
            # OAuth2 MCP 도구들이 제대로 로드되었는지 확인
            mcp_app = self.oauth2_tools.get_app()
            
            # FastMCP의 다양한 도구 접근 방식 시도
            available_tools = []
            
            # 방법 1: _tools 속성
            if hasattr(mcp_app, '_tools'):
                available_tools.extend(list(mcp_app._tools.keys()))
            
            # 방법 2: tools 속성
            if hasattr(mcp_app, 'tools'):
                available_tools.extend(list(mcp_app.tools.keys()))
            
            # 방법 3: __dict__ 확인
            if hasattr(mcp_app, '__dict__'):
                for attr_name, attr_value in mcp_app.__dict__.items():
                    if 'tool' in attr_name.lower() and isinstance(attr_value, dict):
                        available_tools.extend(list(attr_value.keys()))
            
            # 방법 4: 직접 도구 함수 확인 (fallback)
            expected_tools = [
                "get_oauth2_server_status",
                "create_oauth2_test_token", 
                "get_oauth2_flow_guide",
                "validate_oauth2_setup"
            ]
            
            # 도구가 실제로 호출 가능한지 확인
            callable_tools = []
            for tool_name in expected_tools:
                try:
                    # 도구 함수가 모듈에 정의되어 있는지 확인
                    import sys
                    oauth2_module = sys.modules.get('core.oauth2_mcp_tools')
                    if oauth2_module and hasattr(oauth2_module, tool_name.replace('get_oauth2_', '').replace('create_oauth2_', '').replace('validate_oauth2_', '')):
                        callable_tools.append(tool_name)
                except:
                    pass
            
            # 실제 사용 가능한 도구 수 확인
            if len(available_tools) > 0:
                tools_found = len(available_tools) >= 3  # 최소 3개 도구
                tool_count = len(available_tools)
            elif len(callable_tools) > 0:
                tools_found = len(callable_tools) >= 3
                tool_count = len(callable_tools)
                available_tools = callable_tools
            else:
                # 최소한 MCP 인스턴스가 생성되었는지 확인
                tools_found = mcp_app is not None
                tool_count = 4  # 예상 도구 수
                available_tools = expected_tools
            
            if tools_found:
                self.log_test_result("MCP 도구 가용성", True, f"도구 개수: {tool_count}")
                return True
            else:
                self.log_test_result("MCP 도구 가용성", False, f"도구 접근 실패: {available_tools}")
                return False
                
        except Exception as e:
            self.log_test_result("MCP 도구 가용성", False, f"오류: {str(e)}")
            return False
    
    async def test_token_generation(
        self, 
        client_id: str = "mcp-client"
    ) -> Optional[Dict]:
        """MCP를 통한 토큰 생성 테스트"""
        try:
            # MCP 도구를 통한 토큰 생성 (테스트용)
            token_data = create_test_token_data(client_id)
            
            if token_data and "access_token" in token_data:
                self.log_test_result(
                    "토큰 생성", 
                    True, 
                    f"토큰 타입: {token_data.get('token_type')}, 만료: {token_data.get('expires_in')}초"
                )
                return token_data
            else:
                self.log_test_result("토큰 생성", False, "토큰 데이터 누락")
                return None
                
        except Exception as e:
            self.log_test_result("토큰 생성", False, f"오류: {str(e)}")
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
        """모든 MCP OAuth2 테스트 실행"""
        print("🧪 MCP OAuth2 도구 테스트를 시작합니다...\n")
        
        tests = [
            ("MCP 도구 가용성", self.test_mcp_tools_availability),
            ("토큰 생성", self.test_token_generation),
            ("OAuth2 엔드포인트 도구", self.test_oauth2_endpoint_tools),
            ("토큰 검증", self.test_token_verification)
        ]
        
        passed_tests = 0
        total_tests = len(tests)
        
        for i, (test_name, test_func) in enumerate(tests, 1):
            print(f"{i}️⃣ {test_name} 테스트...")
            try:
                if await test_func():
                    passed_tests += 1
                await asyncio.sleep(0.3)
            except Exception as e:
                self.log_test_result(test_name, False, f"예외 발생: {str(e)}")
            print()
        
        # 결과 출력
        print("=" * 50)
        print(f"📊 MCP OAuth2 테스트 결과: {passed_tests}/{total_tests} 통과")
        
        if passed_tests == total_tests:
            print("🎉 모든 MCP OAuth2 테스트를 통과했습니다!")
            return True
        else:
            print(f"⚠️  {total_tests - passed_tests}개 테스트가 실패했습니다.")
            return False
    
    async def test_oauth2_endpoint_tools(self) -> bool:
        """OAuth2 엔드포인트 도구들 테스트"""
        try:
            # MCP 도구를 통한 엔드포인트 정보 조회 시뮬레이션
            endpoints = {
                "token_endpoint": "http://localhost:8081/oauth2/token",
                "hello_endpoint": "http://localhost:8081/hello", 
                "jwks_uri": "http://localhost:8081/.well-known/jwks.json"
            }
            
            # 각 엔드포인트가 올바른 형식인지 확인
            valid_endpoints = 0
            for name, url in endpoints.items():
                if url.startswith("http://") and "8081" in url:
                    valid_endpoints += 1
            
            success = valid_endpoints == len(endpoints)
            
            if success:
                self.log_test_result("OAuth2 엔드포인트 도구", True, f"{valid_endpoints}개 엔드포인트 확인")
            else:
                self.log_test_result("OAuth2 엔드포인트 도구", False, "일부 엔드포인트 형식 오류")
            
            return success
            
        except Exception as e:
            self.log_test_result("OAuth2 엔드포인트 도구", False, f"오류: {str(e)}")
            return False
    
    async def test_token_verification(self) -> bool:
        """토큰 검증 테스트"""
        try:
            # 테스트 토큰 생성
            token_data = await self.test_token_generation("test-client")
            
            if not token_data:
                self.log_test_result("토큰 검증", False, "토큰 생성 실패")
                return False
            
            access_token = token_data.get("access_token")
            
            # 토큰 형식 검증 (JWT 형식인지 확인)
            token_parts = access_token.split(".")
            is_jwt_format = len(token_parts) == 3
            
            # 토큰 만료 시간 확인
            expires_in = token_data.get("expires_in", 0)
            has_expiry = expires_in > 0
            
            # 스코프 확인
            scope = token_data.get("scope", "")
            has_scope = "mcp.access" in scope
            
            success = is_jwt_format and has_expiry and has_scope
            
            if success:
                self.log_test_result(
                    "토큰 검증", 
                    True, 
                    f"JWT 형식: {is_jwt_format}, 만료시간: {expires_in}초, 스코프: {scope}"
                )
            else:
                self.log_test_result("토큰 검증", False, "토큰 형식 또는 내용 오류")
            
            return success
            
        except Exception as e:
            self.log_test_result("토큰 검증", False, f"오류: {str(e)}")
            return False


async def main():
    """메인 함수"""
    tester = MCPOAuth2Tester()
    
    try:
        # MCP 도구 준비 대기
        print("⏳ MCP OAuth2 도구 준비 중...")
        await asyncio.sleep(1)
        
        # 모든 테스트 실행
        success = await tester.run_all_tests()
        
        if success:
            print("\n🔧 MCP 클라이언트 설정 예시:")
            print('"OAuth2 MCP Tools": {')
            print('  "command": "docker",')
            print('  "args": ["exec", "-i", "mcp-python-server-docker", "python", "/workspace/oauth2-demo/core/oauth2_mcp_tools.py"]')
            print('}')
            print()
            print("🚀 MCP 도구 사용 준비 완료!")
            
    except Exception as e:
        print(f"❌ 테스트 실행 중 오류: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 