"""
보안이 적용된 MCP 도구들

OAuth2 인증과 함께 PII 탐지, 암호화, 감사 로깅이 통합된 MCP 도구들을 제공합니다.
실제 기업 환경에서 사용될 수 있는 보안 수준의 데모를 제공합니다.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional, Any

from fastmcp import FastMCP

from .security_common import (
    secure_tool,
    get_pii_detector,
    get_encryption_service,
    get_security_auditor
)


class SecureMCPTools:
    """보안이 적용된 MCP 도구 모음"""
    
    def __init__(self):
        self.mcp = FastMCP("Secure MCP Tools with OAuth2")
        self.setup_tools()
    
    def setup_tools(self):
        """보안 도구들 설정"""
        
        @self.mcp.tool()
        @secure_tool(requires_encryption=False, log_access=True, pii_policy="mask")
        async def get_user_info(
            user_query: str,
            client_id: str = "mcp-client",
            user_id: str = "anonymous"
        ) -> Dict[str, Any]:
            """
            사용자 정보 조회 (PII 마스킹 적용)
            
            Args:
                user_query: 사용자 조회 쿼리
                client_id: OAuth2 클라이언트 ID
                user_id: 사용자 ID
                
            Returns:
                마스킹된 사용자 정보
            """
            # 가상의 사용자 데이터 (실제로는 데이터베이스에서 조회)
            user_data = {
                "query": user_query,
                "timestamp": datetime.now().isoformat(),
                "message": "사용자 정보가 안전하게 조회되었습니다 (PII 마스킹 적용)",
                "client_id": client_id,
                "user_id": user_id
            }
            
            return user_data
        
        @self.mcp.tool()
        @secure_tool(requires_encryption=True, log_access=True, pii_policy="encrypt")
        async def store_sensitive_data(
            customer_name: str,
            customer_email: str,
            customer_phone: str,
            notes: str = "",
            client_id: str = "mcp-client",
            user_id: str = "anonymous"
        ) -> Dict[str, Any]:
            """
            민감한 고객 데이터 저장 (암호화 적용)
            
            Args:
                customer_name: 고객 이름
                customer_email: 고객 이메일
                customer_phone: 고객 전화번호
                notes: 추가 메모
                client_id: OAuth2 클라이언트 ID
                user_id: 사용자 ID
                
            Returns:
                저장 결과 (암호화된 데이터)
            """
            # 실제로는 암호화된 데이터를 데이터베이스에 저장
            storage_result = {
                "success": True,
                "message": "고객 데이터가 암호화되어 안전하게 저장되었습니다",
                "timestamp": datetime.now().isoformat(),
                "client_id": client_id,
                "user_id": user_id,
                "data_encrypted": True,
                "encryption_algorithm": "Fernet (AES 128)",
                "audit_logged": True
            }
            
            return storage_result
        
        @self.mcp.tool()
        @secure_tool(requires_encryption=False, log_access=True, pii_policy="reject")
        async def high_security_operation(
            operation_data: str,
            operation_type: str = "analysis",
            client_id: str = "mcp-client",
            user_id: str = "anonymous"
        ) -> Dict[str, Any]:
            """
            높은 보안 수준이 요구되는 작업 (PII 발견 시 거부)
            
            Args:
                operation_data: 작업 데이터
                operation_type: 작업 유형
                client_id: OAuth2 클라이언트 ID
                user_id: 사용자 ID
                
            Returns:
                작업 결과
            """
            result = {
                "success": True,
                "message": f"{operation_type} 작업이 안전하게 완료되었습니다",
                "operation_type": operation_type,
                "timestamp": datetime.now().isoformat(),
                "client_id": client_id,
                "user_id": user_id,
                "security_level": "HIGH",
                "pii_policy": "REJECT"
            }
            
            return result
        
        @self.mcp.tool()
        async def test_pii_detection(
            test_text: str
        ) -> Dict[str, Any]:
            """
            PII 탐지 테스트 도구
            
            Args:
                test_text: 테스트할 텍스트
                
            Returns:
                PII 탐지 결과
            """
            pii_detector = get_pii_detector()
            detected_pii = pii_detector.scan_text(test_text)
            masked_text = pii_detector.mask_pii(test_text)
            
            return {
                "original_text": test_text,
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
        
        @self.mcp.tool()
        async def test_encryption(
            test_data: str
        ) -> Dict[str, Any]:
            """
            암호화/복호화 테스트 도구
            
            Args:
                test_data: 테스트할 데이터
                
            Returns:
                암호화/복호화 결과
            """
            encryption_service = get_encryption_service()
            
            try:
                # 암호화
                encrypted = encryption_service.encrypt(test_data)
                
                # 복호화
                decrypted = encryption_service.decrypt(encrypted)
                
                return {
                    "success": True,
                    "original_data": test_data,
                    "encrypted_data": encrypted[:50] + "..." if len(encrypted) > 50 else encrypted,
                    "decrypted_data": decrypted,
                    "encryption_verified": test_data == decrypted,
                    "encryption_algorithm": "Fernet (AES 128)",
                    "timestamp": datetime.now().isoformat()
                }
                
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
        
        @self.mcp.tool()
        async def get_security_audit_log(
            limit: int = 10
        ) -> Dict[str, Any]:
            """
            보안 감사 로그 조회
            
            Args:
                limit: 조회할 로그 수
                
            Returns:
                최근 보안 감사 로그
            """
            auditor = get_security_auditor()
            
            try:
                # 실제로는 로그 파일을 읽어서 반환
                with open(auditor.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    recent_logs = lines[-limit:] if len(lines) > limit else lines
                
                parsed_logs = []
                for line in recent_logs:
                    try:
                        # 로그 라인에서 JSON 부분 추출
                        json_start = line.find('{')
                        if json_start != -1:
                            json_part = line[json_start:].strip()
                            log_entry = json.loads(json_part)
                            parsed_logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
                
                return {
                    "success": True,
                    "log_count": len(parsed_logs),
                    "logs": parsed_logs,
                    "log_file": auditor.log_file,
                    "timestamp": datetime.now().isoformat()
                }
                
            except FileNotFoundError:
                return {
                    "success": False,
                    "message": "감사 로그 파일을 찾을 수 없습니다",
                    "log_file": auditor.log_file,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
        
        @self.mcp.tool()
        async def simulate_data_breach_detection(
            suspicious_activity: str,
            severity: str = "MEDIUM"
        ) -> Dict[str, Any]:
            """
            데이터 유출 탐지 시뮬레이션
            
            Args:
                suspicious_activity: 의심스러운 활동 설명
                severity: 심각도 (LOW, MEDIUM, HIGH, CRITICAL)
                
            Returns:
                보안 이벤트 처리 결과
            """
            auditor = get_security_auditor()
            
            # 보안 이벤트 로그 기록
            auditor.log_security_event(
                event_type="potential_data_breach",
                description=f"의심스러운 활동 감지: {suspicious_activity}",
                severity=severity,
                details={
                    "activity": suspicious_activity,
                    "detection_time": datetime.now().isoformat(),
                    "automated_response": "활동 모니터링 강화"
                }
            )
            
            # 심각도에 따른 자동 대응
            response_actions = []
            if severity in ["HIGH", "CRITICAL"]:
                response_actions.extend([
                    "관리자에게 즉시 알림 발송",
                    "관련 세션 모니터링 강화",
                    "추가 인증 요구"
                ])
            elif severity == "MEDIUM":
                response_actions.extend([
                    "활동 로그 상세 기록",
                    "패턴 분석 수행"
                ])
            else:
                response_actions.append("일반 모니터링 유지")
            
            return {
                "success": True,
                "message": "보안 이벤트가 기록되고 적절한 대응이 수행되었습니다",
                "event_id": f"SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "severity": severity,
                "suspicious_activity": suspicious_activity,
                "response_actions": response_actions,
                "timestamp": datetime.now().isoformat()
            }
        
        @self.mcp.tool()
        async def generate_security_report(
            report_type: str = "summary"
        ) -> Dict[str, Any]:
            """
            보안 리포트 생성
            
            Args:
                report_type: 리포트 유형 (summary, detailed)
                
            Returns:
                보안 리포트
            """
            auditor = get_security_auditor()
            
            # 실제로는 로그를 분석해서 통계 생성
            try:
                with open(auditor.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                # 간단한 통계 계산
                total_events = len(lines)
                tool_access_count = sum(1 for line in lines if "tool_access" in line)
                pii_detected_count = sum(1 for line in lines if "contains_pii" in line and "true" in line.lower())
                security_events = sum(1 for line in lines if "potential_data_breach" in line)
                
                report = {
                    "report_type": report_type,
                    "generation_time": datetime.now().isoformat(),
                    "summary": {
                        "total_events": total_events,
                        "tool_access_events": tool_access_count,
                        "pii_detected_events": pii_detected_count,
                        "security_incidents": security_events,
                        "audit_log_file": auditor.log_file
                    }
                }
                
                if report_type == "detailed":
                    report["detailed_analysis"] = {
                        "pii_detection_rate": f"{(pii_detected_count/tool_access_count*100):.1f}%" if tool_access_count > 0 else "0%",
                        "security_incident_rate": f"{(security_events/total_events*100):.1f}%" if total_events > 0 else "0%",
                        "recommendations": [
                            "정기적인 보안 감사 수행",
                            "PII 탐지 패턴 업데이트",
                            "암호화 키 순환",
                            "직원 보안 교육 실시"
                        ]
                    }
                
                return report
                
            except FileNotFoundError:
                return {
                    "report_type": report_type,
                    "generation_time": datetime.now().isoformat(),
                    "error": "감사 로그 파일을 찾을 수 없습니다",
                    "summary": {
                        "total_events": 0,
                        "note": "로그 파일이 생성되지 않았습니다"
                    }
                }
    
    def get_app(self):
        """FastMCP 앱 반환"""
        return self.mcp


# 전역 인스턴스
secure_mcp_tools = SecureMCPTools()


async def main():
    """메인 실행 함수"""
    print("🔐 보안이 적용된 MCP 도구 서버 시작")
    print("사용 가능한 도구:")
    print("- get_user_info: 사용자 정보 조회 (PII 마스킹)")
    print("- store_sensitive_data: 민감한 데이터 저장 (암호화)")
    print("- high_security_operation: 고보안 작업 (PII 거부)")
    print("- test_pii_detection: PII 탐지 테스트")
    print("- test_encryption: 암호화/복호화 테스트")
    print("- get_security_audit_log: 보안 감사 로그 조회")
    print("- simulate_data_breach_detection: 데이터 유출 탐지 시뮬레이션")
    print("- generate_security_report: 보안 리포트 생성")
    
    # MCP 서버 실행
    secure_mcp_tools.mcp.run()


if __name__ == "__main__":
    asyncio.run(main()) 