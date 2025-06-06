#!/usr/bin/env python3
"""
OAuth2 + 보안 기능 통합 테스트 스크립트

이 스크립트는 다음을 테스트합니다:
- OAuth2 인증과 보안 기능의 통합
- PII 탐지 및 마스킹
- 데이터 암호화/복호화
- 보안 감사 로깅
- 보안 정책 적용
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any

import httpx

import sys
import os
# oauth2-demo 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.security_common import (
    PiiDetector,
    EncryptionService,
    SecurityAuditor,
    get_pii_detector,
    get_encryption_service,
    get_security_auditor
)


class SecurityIntegrationTester:
    """OAuth2 + 보안 기능 통합 테스트 클래스"""
    
    def __init__(self, base_url: str = "http://localhost:8081"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        self.access_token = None
        
    async def close(self):
        """HTTP 클라이언트 종료"""
        await self.client.aclose()
    
    async def setup(self) -> bool:
        """테스트 환경 설정"""
        print("🔧 테스트 환경 설정 중...")
        
        # OAuth2 토큰 획득
        token_data = await self.get_oauth2_token()
        if not token_data:
            print("❌ OAuth2 토큰 획득 실패")
            return False
        
        self.access_token = token_data.get("access_token")
        print(f"✅ OAuth2 토큰 획득 성공")
        return True
    
    async def get_oauth2_token(self) -> Optional[Dict]:
        """OAuth2 토큰 획득"""
        try:
            data = {
                "grant_type": "client_credentials",
                "scope": "mcp.access",
                "client_id": "mcp-client",
                "client_secret": "secret"
            }
            
            response = await self.client.post(
                f"{self.base_url}/oauth2/token",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"토큰 요청 실패: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"토큰 요청 중 오류: {e}")
            return None
    
    async def test_pii_detection_basic(self) -> bool:
        """기본 PII 탐지 테스트"""
        print("\n1️⃣ PII 탐지 기본 테스트...")
        
        try:
            # 최신 패턴으로 새로운 인스턴스 생성
            pii_detector = PiiDetector('security/pii_patterns.json')
            
            # 테스트 케이스
            test_cases = [
                {
                    "name": "이메일 탐지",
                    "text": "연락처: john.doe@example.com",
                    "expected_pii": ["email"]
                },
                {
                    "name": "한국 휴대폰 번호 탐지",
                    "text": "전화번호: 010-1234-5678",
                    "expected_pii": ["korean_phone"]
                },
                {
                    "name": "주민등록번호 탐지",
                    "text": "주민등록번호: 123456-1234567",
                    "expected_pii": ["korean_rrn"]
                },
                {
                    "name": "복합 PII 탐지",
                    "text": "고객정보 - 이름: 홍길동님, 이메일: hong@test.com, 전화: 010-9876-5432",
                    "expected_pii": ["name_pattern", "email", "korean_phone"]
                }
            ]
            
            passed_tests = 0
            for test_case in test_cases:
                detected_pii = pii_detector.scan_text(test_case["text"])
                detected_types = [pii_type for pii_type, _ in detected_pii]
                
                # 예상된 PII가 모두 탐지되었는지 확인
                all_detected = all(pii_type in detected_types for pii_type in test_case["expected_pii"])
                
                if all_detected:
                    print(f"   ✅ {test_case['name']}: {detected_types}")
                    passed_tests += 1
                else:
                    print(f"   ❌ {test_case['name']}: 예상 {test_case['expected_pii']}, 탐지 {detected_types}")
            
            success = passed_tests == len(test_cases)
            print(f"   📊 PII 탐지 테스트: {passed_tests}/{len(test_cases)} 통과")
            return success
            
        except Exception as e:
            print(f"   ❌ PII 탐지 테스트 중 오류: {e}")
            return False
    
    async def test_pii_masking(self) -> bool:
        """PII 마스킹 테스트"""
        print("\n2️⃣ PII 마스킹 테스트...")
        
        try:
            pii_detector = get_pii_detector()
            
            test_text = "고객 정보: 홍길동님 (hong@example.com, 010-1234-5678)"
            masked_text = pii_detector.mask_pii(test_text)
            
            # 원본에 PII가 있고, 마스킹된 텍스트에는 없어야 함
            original_pii = pii_detector.scan_text(test_text)
            masked_pii = pii_detector.scan_text(masked_text)
            
            print(f"   원본: {test_text}")
            print(f"   마스킹: {masked_text}")
            print(f"   원본 PII 개수: {len(original_pii)}")
            print(f"   마스킹 후 PII 개수: {len(masked_pii)}")
            
            # 마스킹이 제대로 되었는지 확인
            success = len(original_pii) > 0 and len(masked_pii) < len(original_pii)
            
            if success:
                print(f"   ✅ PII 마스킹 성공")
            else:
                print(f"   ❌ PII 마스킹 실패")
            
            return success
            
        except Exception as e:
            print(f"   ❌ PII 마스킹 테스트 중 오류: {e}")
            return False
    
    async def test_encryption_service(self) -> bool:
        """암호화 서비스 테스트"""
        print("\n3️⃣ 암호화 서비스 테스트...")
        
        try:
            encryption_service = get_encryption_service()
            
            # 다양한 데이터 타입 테스트
            test_cases = [
                {"name": "문자열", "data": "민감한 고객 정보입니다"},
                {"name": "딕셔너리", "data": {"name": "홍길동", "email": "hong@test.com"}},
                {"name": "긴 텍스트", "data": "이것은 매우 긴 텍스트로 암호화 성능을 테스트하기 위한 것입니다. " * 10},
                {"name": "한글 텍스트", "data": "한글 암호화 테스트 - 고객명: 김철수, 연락처: 010-1111-2222"}
            ]
            
            passed_tests = 0
            for test_case in test_cases:
                original_data = test_case["data"]
                
                # 암호화
                encrypted = encryption_service.encrypt(original_data)
                
                # 복호화
                decrypted = encryption_service.decrypt(encrypted)
                
                # 검증
                if original_data == decrypted:
                    print(f"   ✅ {test_case['name']} 암호화/복호화 성공")
                    passed_tests += 1
                else:
                    print(f"   ❌ {test_case['name']} 암호화/복호화 실패")
                    print(f"      원본: {original_data}")
                    print(f"      복호화: {decrypted}")
            
            success = passed_tests == len(test_cases)
            print(f"   📊 암호화 테스트: {passed_tests}/{len(test_cases)} 통과")
            return success
            
        except Exception as e:
            print(f"   ❌ 암호화 서비스 테스트 중 오류: {e}")
            return False
    
    async def test_security_auditing(self) -> bool:
        """보안 감사 로깅 테스트"""
        print("\n4️⃣ 보안 감사 로깅 테스트...")
        
        try:
            auditor = get_security_auditor()
            
            # 테스트 로그 기록
            test_events = [
                {
                    "type": "tool_access",
                    "method": "log_access",
                    "args": {
                        "tool_name": "test_tool",
                        "user_id": "test_user",
                        "client_id": "test_client",
                        "parameters": {"query": "test"},
                        "contains_pii": True,
                        "action_taken": "executed"
                    }
                },
                {
                    "type": "security_event",
                    "method": "log_security_event",
                    "args": {
                        "event_type": "test_security_event",
                        "description": "보안 테스트 이벤트",
                        "severity": "INFO",
                        "details": {"test": True}
                    }
                }
            ]
            
            # 로그 기록
            for event in test_events:
                if event["method"] == "log_access":
                    auditor.log_access(**event["args"])
                elif event["method"] == "log_security_event":
                    auditor.log_security_event(**event["args"])
            
            # 로그 파일 확인
            try:
                with open(auditor.log_file, "r", encoding="utf-8") as f:
                    log_content = f.read()
                    
                # 기록된 이벤트들이 로그에 있는지 확인
                logged_events = 0
                for event in test_events:
                    if "tool_name" in event["args"] and event["args"]["tool_name"] in log_content:
                        logged_events += 1
                    elif "event_type" in event["args"] and event["args"]["event_type"] in log_content:
                        logged_events += 1
                
                success = logged_events == len(test_events)
                
                if success:
                    print(f"   ✅ {logged_events}/{len(test_events)} 이벤트가 성공적으로 로깅됨")
                    print(f"   📁 로그 파일: {auditor.log_file}")
                else:
                    print(f"   ❌ {logged_events}/{len(test_events)} 이벤트만 로깅됨")
                
                return success
                
            except FileNotFoundError:
                print(f"   ❌ 로그 파일을 찾을 수 없음: {auditor.log_file}")
                return False
            
        except Exception as e:
            print(f"   ❌ 보안 감사 로깅 테스트 중 오류: {e}")
            return False
    
    async def test_oauth2_with_security(self) -> bool:
        """OAuth2 인증과 보안 기능 통합 테스트"""
        print("\n5️⃣ OAuth2 + 보안 통합 테스트...")
        
        if not self.access_token:
            print("   ❌ OAuth2 토큰이 없습니다")
            return False
        
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # 1. 일반 보호된 엔드포인트 접근
            response = await self.client.get(f"{self.base_url}/hello", headers=headers)
            
            if response.status_code == 200:
                print("   ✅ OAuth2 보호된 엔드포인트 접근 성공")
                data = response.json()
                print(f"      메시지: {data.get('message')}")
            else:
                print(f"   ❌ OAuth2 보호된 엔드포인트 접근 실패: {response.status_code}")
                return False
            
            # 2. 인증 없는 접근 시도 (실패해야 함)
            response_no_auth = await self.client.get(f"{self.base_url}/hello")
            
            if response_no_auth.status_code == 401:
                print("   ✅ 인증 없는 접근이 올바르게 차단됨")
            else:
                print(f"   ❌ 인증 없는 접근이 차단되지 않음: {response_no_auth.status_code}")
                return False
            
            # 3. 잘못된 토큰으로 접근 시도 (실패해야 함)
            invalid_headers = {"Authorization": "Bearer invalid_token"}
            response_invalid = await self.client.get(f"{self.base_url}/hello", headers=invalid_headers)
            
            if response_invalid.status_code == 401:
                print("   ✅ 잘못된 토큰이 올바르게 거부됨")
            else:
                print(f"   ❌ 잘못된 토큰이 거부되지 않음: {response_invalid.status_code}")
                return False
            
            return True
            
        except Exception as e:
            print(f"   ❌ OAuth2 + 보안 통합 테스트 중 오류: {e}")
            return False
    
    async def test_secure_tool_simulation(self) -> bool:
        """보안 도구 시뮬레이션 테스트"""
        print("\n6️⃣ 보안 도구 시뮬레이션 테스트...")
        
        try:
            # 보안 도구 임포트 및 테스트
            from security.security_common import secure_tool
            
            # 테스트용 도구 정의
            @secure_tool(requires_encryption=True, log_access=True, pii_policy="encrypt")
            async def test_secure_tool(user_data: str, client_id: str = "test", user_id: str = "test"):
                return {"processed": True, "data": user_data}
            
            # PII가 포함된 데이터로 테스트
            test_data = "고객 이메일: test@example.com, 전화: 010-1234-5678"
            
            try:
                result = await test_secure_tool(
                    user_data=test_data,
                    client_id="test_client",
                    user_id="test_user"
                )
                print("   ✅ 보안 도구 시뮬레이션 성공")
                print(f"      결과: {result}")
                return True
                
            except Exception as tool_error:
                print(f"   ❌ 보안 도구 실행 중 오류: {tool_error}")
                return False
            
        except Exception as e:
            print(f"   ❌ 보안 도구 시뮬레이션 테스트 중 오류: {e}")
            return False
    
    async def test_comprehensive_security_scenario(self) -> bool:
        """종합 보안 시나리오 테스트"""
        print("\n7️⃣ 종합 보안 시나리오 테스트...")
        
        try:
            # 실제 기업 환경 시나리오 시뮬레이션
            pii_detector = get_pii_detector()
            encryption_service = get_encryption_service()
            auditor = get_security_auditor()
            
            # 시나리오: 고객 정보 처리 과정
            customer_data = {
                "name": "홍길동님",
                "email": "hong.gildong@company.com",
                "phone": "010-1234-5678",
                "address": "서울시 강남구 테헤란로 123",
                "notes": "VIP 고객 - 특별 관리 필요"
            }
            
            print(f"   📋 시나리오: 고객 정보 처리")
            print(f"      고객명: {customer_data['name']}")
            
            # 1단계: PII 탐지
            detected_pii = []
            for field, value in customer_data.items():
                if isinstance(value, str):
                    field_pii = pii_detector.scan_text(value)
                    if field_pii:
                        detected_pii.extend([(field, pii_type, matches) for pii_type, matches in field_pii])
            
            print(f"      🔍 PII 탐지: {len(detected_pii)}개 항목")
            
            # 2단계: 민감한 데이터 암호화
            encrypted_data = {}
            for field, value in customer_data.items():
                if field in ["email", "phone", "address"]:  # 민감한 필드
                    encrypted_data[field] = encryption_service.encrypt(value)
                else:
                    encrypted_data[field] = value
            
            print(f"      🔐 암호화: {len([k for k, v in encrypted_data.items() if k in ['email', 'phone', 'address']])}개 필드")
            
            # 3단계: 감사 로그 기록
            auditor.log_access(
                tool_name="customer_data_processing",
                user_id="manager_kim",
                client_id="crm_system",
                parameters={k: "***" for k in customer_data.keys()},
                contains_pii=len(detected_pii) > 0,
                action_taken="processed_with_encryption"
            )
            
            # 4단계: 데이터 복호화 (권한이 있는 경우)
            decrypted_data = {}
            for field, value in encrypted_data.items():
                if field in ["email", "phone", "address"]:
                    try:
                        decrypted_data[field] = encryption_service.decrypt(value)
                    except:
                        decrypted_data[field] = "[복호화 실패]"
                else:
                    decrypted_data[field] = value
            
            # 검증: 원본과 복호화된 데이터가 일치하는가?
            data_integrity = all(
                customer_data[field] == decrypted_data[field]
                for field in customer_data.keys()
            )
            
            if data_integrity:
                print(f"      ✅ 데이터 무결성 검증 성공")
                print(f"      📊 처리 결과:")
                print(f"         - PII 탐지: {len(detected_pii)}개")
                print(f"         - 암호화 필드: 3개")
                print(f"         - 감사 로그: 기록됨")
                print(f"         - 데이터 무결성: 유지됨")
                return True
            else:
                print(f"      ❌ 데이터 무결성 검증 실패")
                return False
            
        except Exception as e:
            print(f"   ❌ 종합 보안 시나리오 테스트 중 오류: {e}")
            return False
    
    async def run_all_tests(self) -> bool:
        """모든 보안 테스트 실행"""
        print("🧪 OAuth2 + 보안 기능 통합 테스트를 시작합니다...\n")
        
        # 환경 설정
        if not await self.setup():
            return False
        
        tests = [
            ("PII 탐지 기본", self.test_pii_detection_basic),
            ("PII 마스킹", self.test_pii_masking),
            ("암호화 서비스", self.test_encryption_service),
            ("보안 감사 로깅", self.test_security_auditing),
            ("OAuth2 + 보안 통합", self.test_oauth2_with_security),
            ("보안 도구 시뮬레이션", self.test_secure_tool_simulation),
            ("종합 보안 시나리오", self.test_comprehensive_security_scenario)
        ]
        
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, test_func in tests:
            try:
                if await test_func():
                    passed_tests += 1
                time.sleep(0.5)  # 테스트 간 간격
            except Exception as e:
                print(f"❌ {test_name} 테스트 중 예외 발생: {e}")
        
        print(f"\n" + "=" * 60)
        print(f"📊 통합 보안 테스트 결과: {passed_tests}/{total_tests} 통과")
        
        if passed_tests == total_tests:
            print("🎉 모든 보안 테스트를 통과했습니다!")
            print("\n🔐 보안 기능 상태:")
            print("   ✅ PII 탐지 및 마스킹")
            print("   ✅ 데이터 암호화/복호화")
            print("   ✅ 보안 감사 로깅")
            print("   ✅ OAuth2 인증 통합")
            print("   ✅ 보안 정책 적용")
            return True
        else:
            print(f"⚠️  {total_tests - passed_tests}개 테스트가 실패했습니다.")
            print("보안 구성을 점검해 주세요.")
            return False


async def main():
    """메인 함수"""
    tester = SecurityIntegrationTester()
    
    try:
        print("⏳ 서버 준비 대기 중...")
        await asyncio.sleep(2)
        
        # 모든 테스트 실행
        success = await tester.run_all_tests()
        
        if success:
            print(f"\n🔍 추가 보안 테스트 명령어:")
            print("# PII 탐지 테스트:")
            print("python -c \"from security_common import get_pii_detector; p=get_pii_detector(); print(p.scan_text('이메일: test@example.com'))\"")
            print()
            print("# 암호화 테스트:")
            print("python -c \"from security_common import get_encryption_service; e=get_encryption_service(); enc=e.encrypt('테스트'); print(f'암호화: {enc[:30]}...'); print(f'복호화: {e.decrypt(enc)}')\"")
            
    finally:
        await tester.close()


if __name__ == "__main__":
    asyncio.run(main()) 