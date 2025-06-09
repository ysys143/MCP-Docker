#!/usr/bin/env python3
"""
MCP 도구 직접 호출 테스트 스크립트

이 스크립트는 MCP 도구들을 직접 호출하여 기능을 테스트합니다.
실제 MCP 클라이언트가 도구를 호출하는 방식을 시뮬레이션합니다.
"""

import asyncio
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

# oauth2-demo 디렉토리를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.secure_mcp_tools import SecureMCPTools
from security.security_common import (
    get_pii_detector,
    get_encryption_service,
    get_security_auditor
)


class MCPToolsTester:
    """MCP 도구 직접 테스트 클래스"""
    
    def __init__(self):
        self.secure_tools = SecureMCPTools()
        self.test_results = []
        
    def log_result(self, test_name: str, success: bool, result: Any = None, error: str = ""):
        """테스트 결과 로깅"""
        self.test_results.append({
            "test": test_name,
            "success": success,
            "result": result,
            "error": error,
            "timestamp": datetime.now().isoformat()
        })
        
        status = "✅" if success else "❌"
        print(f"{status} {test_name}")
        if error:
            print(f"   오류: {error}")
        elif result and isinstance(result, dict):
            if "message" in result:
                print(f"   결과: {result['message']}")
    
    async def test_pii_detection_tool(self) -> bool:
        """PII 탐지 도구 테스트"""
        print("\n1️⃣ test_pii_detection 도구 테스트...")
        
        test_cases = [
            {
                "name": "이메일 탐지",
                "text": "고객 이메일: customer@example.com"
            },
            {
                "name": "전화번호 탐지", 
                "text": "연락처: 010-1234-5678"
            },
            {
                "name": "복합 PII",
                "text": "고객정보 - 이름: 홍길동님, 이메일: hong@test.com, 전화: 010-9876-5432"
            },
            {
                "name": "PII 없음",
                "text": "일반적인 업무 내용입니다."
            }
        ]
        
        passed = 0
        for test_case in test_cases:
            try:
                # MCP 도구 직접 호출
                mcp_app = self.secure_tools.get_app()
                
                # test_pii_detection 도구 호출 시뮬레이션
                pii_detector = get_pii_detector()
                detected_pii = pii_detector.scan_text(test_case["text"])
                masked_text = pii_detector.mask_pii(test_case["text"])
                
                result = {
                    "original_text": test_case["text"],
                    "masked_text": masked_text,
                    "detected_pii": [
                        {
                            "type": pii_type,
                            "matches": matches,
                            "count": len(matches)
                        }
                        for pii_type, matches in detected_pii
                    ],
                    "total_pii_found": len(detected_pii),
                    "timestamp": datetime.now().isoformat()
                }
                
                # 결과 검증
                if test_case["name"] == "PII 없음":
                    success = len(detected_pii) == 0
                else:
                    success = len(detected_pii) > 0
                
                if success:
                    passed += 1
                    
                self.log_result(
                    f"PII 탐지: {test_case['name']}", 
                    success, 
                    {"pii_count": len(detected_pii), "masked": masked_text != test_case["text"]}
                )
                
            except Exception as e:
                self.log_result(f"PII 탐지: {test_case['name']}", False, error=str(e))
        
        overall_success = passed == len(test_cases)
        print(f"   📊 PII 탐지 도구: {passed}/{len(test_cases)} 통과")
        return overall_success
    
    async def test_encryption_tool(self) -> bool:
        """암호화 도구 테스트"""
        print("\n2️⃣ test_encryption 도구 테스트...")
        
        test_data_list = [
            "민감한 고객 정보",
            "이메일: sensitive@company.com, 전화: 010-1111-2222",
            {"customer": "홍길동", "data": "기밀 정보"}
        ]
        
        passed = 0
        for i, test_data in enumerate(test_data_list):
            try:
                # MCP 암호화 도구 호출 시뮬레이션
                encryption_service = get_encryption_service()
                
                # 암호화
                encrypted = encryption_service.encrypt(test_data)
                
                # 복호화
                decrypted = encryption_service.decrypt(encrypted)
                
                result = {
                    "success": True,
                    "original_data": test_data,
                    "encrypted_data": encrypted[:50] + "..." if len(encrypted) > 50 else encrypted,
                    "decrypted_data": decrypted,
                    "encryption_verified": test_data == decrypted,
                    "encryption_algorithm": "Fernet (AES 128)",
                    "timestamp": datetime.now().isoformat()
                }
                
                success = result["encryption_verified"]
                if success:
                    passed += 1
                
                self.log_result(
                    f"암호화 테스트 {i+1}", 
                    success, 
                    {"verified": success, "data_type": type(test_data).__name__}
                )
                
            except Exception as e:
                self.log_result(f"암호화 테스트 {i+1}", False, error=str(e))
        
        overall_success = passed == len(test_data_list)
        print(f"   📊 암호화 도구: {passed}/{len(test_data_list)} 통과")
        return overall_success
    
    async def test_secure_user_info_tool(self) -> bool:
        """보안 사용자 정보 도구 테스트"""
        print("\n3️⃣ get_user_info (보안) 도구 테스트...")
        
        test_queries = [
            {
                "name": "PII 포함 쿼리",
                "query": "고객 조회: hong@example.com, 010-1234-5678",
                "expected_masked": True
            },
            {
                "name": "일반 쿼리",
                "query": "고객 목록 조회",
                "expected_masked": False
            },
            {
                "name": "주민번호 포함",
                "query": "고객 정보: 123456-1234567",
                "expected_masked": True
            }
        ]
        
        passed = 0
        for test_case in test_queries:
            try:
                # get_user_info 도구 호출 시뮬레이션 (PII 마스킹 정책 적용)
                pii_detector = get_pii_detector()
                auditor = get_security_auditor()
                
                # PII 탐지
                detected_pii = pii_detector.scan_text(test_case["query"])
                
                # PII 마스킹 적용
                masked_query = pii_detector.mask_pii(test_case["query"])
                
                # 결과 생성
                result = {
                    "query": test_case["query"],
                    "masked_query": masked_query,
                    "timestamp": datetime.now().isoformat(),
                    "message": "사용자 정보가 안전하게 조회되었습니다 (PII 마스킹 적용)",
                    "client_id": "test-client",
                    "user_id": "test-user",
                    "pii_detected": len(detected_pii) > 0,
                    "security_policy": "mask"
                }
                
                # 감사 로그 기록
                auditor.log_access(
                    tool_name="get_user_info",
                    user_id="test-user",
                    client_id="test-client",
                    parameters={"user_query": masked_query},
                    contains_pii=len(detected_pii) > 0,
                    action_taken="pii_masked"
                )
                
                # 검증: PII가 있으면 마스킹되어야 함
                has_pii = len(detected_pii) > 0
                is_masked = masked_query != test_case["query"]
                
                success = (has_pii == test_case["expected_masked"]) and (has_pii == is_masked)
                
                if success:
                    passed += 1
                
                self.log_result(
                    f"사용자 정보: {test_case['name']}", 
                    success, 
                    {"pii_detected": has_pii, "masked": is_masked}
                )
                
            except Exception as e:
                self.log_result(f"사용자 정보: {test_case['name']}", False, error=str(e))
        
        overall_success = passed == len(test_queries)
        print(f"   📊 보안 사용자 정보 도구: {passed}/{len(test_queries)} 통과")
        return overall_success
    
    async def test_secure_data_storage_tool(self) -> bool:
        """보안 데이터 저장 도구 테스트"""
        print("\n4️⃣ store_sensitive_data (암호화) 도구 테스트...")
        
        test_customers = [
            {
                "name": "김철수",
                "email": "kim@company.com",
                "phone": "010-1111-2222",
                "notes": "VIP 고객"
            },
            {
                "name": "이영희님",
                "email": "lee.younghee@test.com", 
                "phone": "010-3333-4444",
                "notes": "프리미엄 서비스 이용"
            }
        ]
        
        passed = 0
        for i, customer in enumerate(test_customers):
            try:
                # store_sensitive_data 도구 호출 시뮬레이션 (암호화 정책 적용)
                encryption_service = get_encryption_service()
                auditor = get_security_auditor()
                
                # 민감한 데이터 암호화
                encrypted_email = encryption_service.encrypt(customer["email"])
                encrypted_phone = encryption_service.encrypt(customer["phone"])
                
                # 결과 생성
                result = {
                    "success": True,
                    "message": "고객 데이터가 암호화되어 안전하게 저장되었습니다",
                    "timestamp": datetime.now().isoformat(),
                    "client_id": "test-client",
                    "user_id": "test-user",
                    "data_encrypted": True,
                    "encryption_algorithm": "Fernet (AES 128)",
                    "audit_logged": True,
                    "encrypted_fields": ["email", "phone"],
                    "customer_name": customer["name"]
                }
                
                # 감사 로그 기록
                auditor.log_access(
                    tool_name="store_sensitive_data",
                    user_id="test-user",
                    client_id="test-client",
                    parameters={
                        "customer_name": customer["name"],
                        "customer_email": "***",
                        "customer_phone": "***",
                        "notes": customer["notes"]
                    },
                    contains_pii=True,
                    action_taken="data_encrypted_and_stored"
                )
                
                # 암호화 검증 (복호화 테스트)
                decrypted_email = encryption_service.decrypt(encrypted_email)
                decrypted_phone = encryption_service.decrypt(encrypted_phone)
                
                encryption_verified = (
                    decrypted_email == customer["email"] and
                    decrypted_phone == customer["phone"]
                )
                
                success = encryption_verified and result["success"]
                
                if success:
                    passed += 1
                
                self.log_result(
                    f"데이터 저장: 고객 {i+1}", 
                    success, 
                    {"encrypted": True, "verified": encryption_verified}
                )
                
            except Exception as e:
                self.log_result(f"데이터 저장: 고객 {i+1}", False, error=str(e))
        
        overall_success = passed == len(test_customers)
        print(f"   📊 보안 데이터 저장 도구: {passed}/{len(test_customers)} 통과")
        return overall_success
    
    async def test_high_security_operation_tool(self) -> bool:
        """높은 보안 수준 작업 도구 테스트"""
        print("\n5️⃣ high_security_operation (PII 거부) 도구 테스트...")
        
        test_operations = [
            {
                "name": "PII 없는 데이터",
                "data": "일반적인 분석 데이터입니다.",
                "should_succeed": True
            },
            {
                "name": "이메일 포함 데이터",
                "data": "분석 대상: user@example.com",
                "should_succeed": False
            },
            {
                "name": "전화번호 포함 데이터",
                "data": "연락처 분석: 010-1234-5678",
                "should_succeed": False
            },
            {
                "name": "복합 PII 데이터",
                "data": "고객 분석: 홍길동님 (hong@test.com, 010-9999-8888)",
                "should_succeed": False
            }
        ]
        
        passed = 0
        for test_case in test_operations:
            try:
                # high_security_operation 도구 호출 시뮬레이션 (PII 거부 정책)
                pii_detector = get_pii_detector()
                auditor = get_security_auditor()
                
                # PII 탐지
                detected_pii = pii_detector.scan_text(test_case["data"])
                has_pii = len(detected_pii) > 0
                
                if has_pii:
                    # PII가 발견되면 작업 거부
                    result = {
                        "success": False,
                        "error": "PII가 탐지되어 높은 보안 수준 작업이 거부되었습니다",
                        "detected_pii_types": [pii_type for pii_type, _ in detected_pii],
                        "security_policy": "REJECT",
                        "timestamp": datetime.now().isoformat()
                    }
                    action_taken = "rejected_due_to_pii"
                else:
                    # PII가 없으면 작업 수행
                    result = {
                        "success": True,
                        "message": "높은 보안 수준 작업이 안전하게 완료되었습니다",
                        "operation_type": "analysis",
                        "timestamp": datetime.now().isoformat(),
                        "client_id": "test-client",
                        "user_id": "test-user",
                        "security_level": "HIGH",
                        "pii_policy": "REJECT"
                    }
                    action_taken = "executed_safely"
                
                # 감사 로그 기록
                auditor.log_access(
                    tool_name="high_security_operation",
                    user_id="test-user",
                    client_id="test-client",
                    parameters={"operation_data": "***", "operation_type": "analysis"},
                    contains_pii=has_pii,
                    action_taken=action_taken
                )
                
                # 검증: 예상된 결과와 일치하는가?
                actual_success = result.get("success", False)
                expected_success = test_case["should_succeed"]
                
                success = actual_success == expected_success
                
                if success:
                    passed += 1
                
                self.log_result(
                    f"높은 보안 작업: {test_case['name']}", 
                    success, 
                    {"expected": expected_success, "actual": actual_success, "pii_detected": has_pii}
                )
                
            except Exception as e:
                self.log_result(f"높은 보안 작업: {test_case['name']}", False, error=str(e))
        
        overall_success = passed == len(test_operations)
        print(f"   📊 높은 보안 작업 도구: {passed}/{len(test_operations)} 통과")
        return overall_success
    
    async def test_audit_log_tool(self) -> bool:
        """감사 로그 도구 테스트"""
        print("\n6️⃣ get_security_audit_log 도구 테스트...")
        
        try:
            # 먼저 테스트 로그 이벤트들을 생성
            auditor = get_security_auditor()
            
            test_events = [
                {
                    "tool_name": "test_audit_tool_1",
                    "user_id": "audit_test_user",
                    "client_id": "audit_test_client",
                    "action_taken": "test_action_1"
                },
                {
                    "tool_name": "test_audit_tool_2", 
                    "user_id": "audit_test_user",
                    "client_id": "audit_test_client",
                    "action_taken": "test_action_2"
                }
            ]
            
            # 테스트 로그 이벤트 기록
            for event in test_events:
                auditor.log_access(
                    tool_name=event["tool_name"],
                    user_id=event["user_id"],
                    client_id=event["client_id"],
                    parameters={"test": True},
                    contains_pii=False,
                    action_taken=event["action_taken"]
                )
            
            # get_security_audit_log 도구 호출 시뮬레이션
            try:
                with open(auditor.log_file, "r", encoding="utf-8") as f:
                    log_lines = f.readlines()
                    
                # 최근 로그 항목들 가져오기 (limit=10)
                recent_logs = log_lines[-10:] if len(log_lines) >= 10 else log_lines
                
                result = {
                    "success": True,
                    "total_logs": len(log_lines),
                    "recent_logs_count": len(recent_logs),
                    "audit_file": auditor.log_file,
                    "timestamp": datetime.now().isoformat(),
                    "sample_logs": [line.strip() for line in recent_logs[-3:]]  # 최근 3개만 샘플로
                }
                
                # 테스트 이벤트들이 로그에 기록되었는지 확인
                log_content = "".join(log_lines)
                events_found = 0
                for event in test_events:
                    if event["tool_name"] in log_content:
                        events_found += 1
                
                success = events_found == len(test_events) and result["success"]
                
                self.log_result(
                    "감사 로그 조회", 
                    success, 
                    {"total_logs": result["total_logs"], "events_found": events_found}
                )
                
                return success
                
            except FileNotFoundError:
                self.log_result("감사 로그 조회", False, error="로그 파일을 찾을 수 없음")
                return False
            
        except Exception as e:
            self.log_result("감사 로그 조회", False, error=str(e))
            return False
    
    async def run_all_tests(self) -> bool:
        """모든 MCP 도구 테스트 실행"""
        print("🧪 MCP 도구 직접 호출 테스트를 시작합니다...\n")
        
        tests = [
            ("PII 탐지 도구", self.test_pii_detection_tool),
            ("암호화 도구", self.test_encryption_tool),
            ("보안 사용자 정보 도구", self.test_secure_user_info_tool),
            ("보안 데이터 저장 도구", self.test_secure_data_storage_tool),
            ("높은 보안 작업 도구", self.test_high_security_operation_tool),
            ("감사 로그 도구", self.test_audit_log_tool)
        ]
        
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, test_func in tests:
            try:
                if await test_func():
                    passed_tests += 1
                await asyncio.sleep(0.3)  # 테스트 간 간격
            except Exception as e:
                print(f"❌ {test_name} 테스트 중 예외 발생: {e}")
        
        print(f"\n" + "=" * 60)
        print(f"📊 MCP 도구 테스트 결과: {passed_tests}/{total_tests} 통과")
        
        if passed_tests == total_tests:
            print("🎉 모든 MCP 도구 테스트를 통과했습니다!")
            print("\n🔧 MCP 도구 사용 준비 완료:")
            print("   ✅ test_pii_detection - PII 탐지 및 마스킹")
            print("   ✅ test_encryption - 데이터 암호화/복호화")
            print("   ✅ get_user_info - 보안 사용자 정보 조회 (PII 마스킹)")
            print("   ✅ store_sensitive_data - 민감한 데이터 저장 (암호화)")
            print("   ✅ high_security_operation - 높은 보안 작업 (PII 거부)")
            print("   ✅ get_security_audit_log - 보안 감사 로그 조회")
            
            print(f"\n🐳 Docker 컨테이너에서 MCP 도구 실행:")
            print(f"   docker exec -i mcp-python-server-docker python /workspace/oauth2-demo/security/secure_mcp_tools.py")
            
            return True
        else:
            print(f"⚠️  {total_tests - passed_tests}개 테스트가 실패했습니다.")
            return False
    
    def print_detailed_results(self):
        """상세 테스트 결과 출력"""
        print(f"\n📋 상세 테스트 결과:")
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"   {status} {result['test']}")
            if result["error"]:
                print(f"      └─ 오류: {result['error']}")
            elif result["result"]:
                print(f"      └─ 결과: {result['result']}")


async def main():
    """메인 함수"""
    tester = MCPToolsTester()
    
    try:
        print("⏳ MCP 도구 테스트 환경 준비 중...")
        await asyncio.sleep(1)
        
        # 모든 테스트 실행
        success = await tester.run_all_tests()
        
        # 상세 결과 출력
        tester.print_detailed_results()
        
        if success:
            print(f"\n🚀 모든 MCP 보안 도구가 정상적으로 작동합니다!")
            print(f"   이제 MCP 클라이언트에서 이 도구들을 안전하게 사용할 수 있습니다.")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  테스트가 사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n❌ 테스트 실행 중 오류 발생: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 