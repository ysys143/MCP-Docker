"""
보안 공통 모듈

이 모듈은 MCP OAuth2 데모에서 사용되는 보안 기능들을 제공합니다:
- PII (개인 식별 정보) 탐지
- 데이터 암호화/복호화
- 보안 데코레이터
- 감사 로깅
"""

import json
import logging
import os
import re
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional, Tuple, Any

from cryptography.fernet import Fernet


# 로깅 설정
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger("security")


class PiiDetector:
    """PII (개인 식별 정보) 탐지기"""
    
    def __init__(self, patterns_file: str = None):
        """
        PII 탐지기 초기화
        
        Args:
            patterns_file: PII 패턴이 정의된 JSON 파일 경로
        """
        if patterns_file is None:
            patterns_file = "pii_patterns.json"
        self.patterns = self._load_patterns(patterns_file)
    
    def _load_patterns(self, patterns_file: str = None) -> Dict[str, str]:
        """PII 패턴 로드"""
        default_patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            "korean_rrn": r'\b\d{6}-[1-4]\d{6}\b',  # 주민등록번호
            "korean_phone": r'\b01[016789]-\d{3,4}-\d{4}\b',  # 한국 휴대폰번호
        }
        
        if patterns_file and os.path.exists(patterns_file):
            try:
                with open(patterns_file, "r", encoding="utf-8") as f:
                    file_patterns = json.load(f)
                    default_patterns.update(file_patterns)
            except Exception as e:
                security_logger.warning(f"PII 패턴 파일 로드 실패: {e}, 기본 패턴 사용")
        
        return default_patterns
    
    def scan_text(self, text: str) -> List[Tuple[str, List[str]]]:
        """
        텍스트에서 PII를 스캔하고 탐지된 PII 유형과 매치된 값들을 반환
        
        Args:
            text: 스캔할 텍스트
            
        Returns:
            List of (pii_type, matched_values) tuples
        """
        detected_pii = []
        
        for pii_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                detected_pii.append((pii_type, matches))
        
        return detected_pii
    
    def scan_parameters(self, parameters: Dict[str, Any]) -> List[Tuple[str, str, List[str]]]:
        """
        요청 매개변수에서 PII 스캔
        
        Args:
            parameters: 스캔할 매개변수 딕셔너리
            
        Returns:
            List of (param_name, pii_type, matched_values) tuples
        """
        detected_pii = []
        
        for param_name, value in parameters.items():
            if isinstance(value, str):
                pii_in_value = self.scan_text(value)
                for pii_type, matches in pii_in_value:
                    detected_pii.append((param_name, pii_type, matches))
        
        return detected_pii
    
    def mask_pii(self, text: str, mask_char: str = "*") -> str:
        """
        텍스트에서 PII를 마스킹
        
        Args:
            text: 마스킹할 텍스트
            mask_char: 마스킹에 사용할 문자
            
        Returns:
            PII가 마스킹된 텍스트
        """
        masked_text = text
        
        for pii_type, pattern in self.patterns.items():
            # 이메일은 @ 앞부분만 마스킹
            if pii_type == "email":
                masked_text = re.sub(
                    pattern,
                    lambda m: f"{mask_char * 3}@{m.group().split('@')[1]}",
                    masked_text,
                    flags=re.IGNORECASE
                )
            else:
                # 다른 PII는 완전히 마스킹
                masked_text = re.sub(
                    pattern,
                    lambda m: mask_char * len(m.group()),
                    masked_text,
                    flags=re.IGNORECASE
                )
        
        return masked_text


class EncryptionService:
    """민감한 데이터 보호를 위한 암호화 서비스"""
    
    def __init__(self, key_path: str = None):
        """
        암호화 서비스 초기화
        
        Args:
            key_path: 암호화 키 파일 경로
        """
        self.key_path = key_path or "keys/encryption.key"
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_generate_key(self) -> bytes:
        """암호화 키 로드 또는 생성"""
        # 키 디렉토리 생성
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as key_file:
                return key_file.read()
        else:
            # 새 키 생성 및 저장
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as key_file:
                key_file.write(key)
            security_logger.info(f"새 암호화 키 생성: {self.key_path}")
            return key
    
    def encrypt(self, data: Any) -> str:
        """
        데이터 암호화
        
        Args:
            data: 암호화할 데이터
            
        Returns:
            암호화된 데이터 (base64 문자열)
        """
        if data is None:
            return None
        
        if isinstance(data, str):
            plaintext = data.encode('utf-8')
        else:
            plaintext = json.dumps(data, ensure_ascii=False).encode('utf-8')
        
        encrypted = self.cipher.encrypt(plaintext)
        return encrypted.decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> Any:
        """
        데이터 복호화
        
        Args:
            encrypted_data: 암호화된 데이터 (base64 문자열)
            
        Returns:
            복호화된 데이터
        """
        if encrypted_data is None:
            return None
        
        try:
            encrypted_bytes = encrypted_data.encode('utf-8')
            decrypted = self.cipher.decrypt(encrypted_bytes)
            decrypted_str = decrypted.decode('utf-8')
            
            # JSON으로 파싱 시도
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str
                
        except Exception as e:
            security_logger.error(f"복호화 실패: {e}")
            raise ValueError("복호화에 실패했습니다")


class SecurityAuditor:
    """보안 감사 로그 관리"""
    
    def __init__(self, log_file: str = "logs/security_audit.log"):
        """
        보안 감사자 초기화
        
        Args:
            log_file: 감사 로그 파일 경로
        """
        self.log_file = log_file
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # 감사 로그용 별도 로거 설정
        self.audit_logger = logging.getLogger("security_audit")
        self.audit_logger.setLevel(logging.INFO)
        
        # 파일 핸들러 추가
        if not self.audit_logger.handlers:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            self.audit_logger.addHandler(file_handler)
    
    def log_access(
        self,
        tool_name: str,
        user_id: str = "anonymous",
        client_id: str = "unknown",
        parameters: Dict[str, Any] = None,
        contains_pii: bool = False,
        action_taken: str = "executed"
    ):
        """
        도구 접근 로그 기록
        
        Args:
            tool_name: 실행된 도구 이름
            user_id: 사용자 ID
            client_id: 클라이언트 ID
            parameters: 요청 매개변수 (마스킹된 버전)
            contains_pii: PII 포함 여부
            action_taken: 수행된 액션
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "tool_access",
            "tool_name": tool_name,
            "user_id": user_id,
            "client_id": client_id,
            "contains_pii": contains_pii,
            "action_taken": action_taken,
            "parameter_count": len(parameters) if parameters else 0
        }
        
        self.audit_logger.info(json.dumps(log_entry, ensure_ascii=False))
    
    def log_security_event(
        self,
        event_type: str,
        description: str,
        severity: str = "INFO",
        details: Dict[str, Any] = None
    ):
        """
        보안 이벤트 로그 기록
        
        Args:
            event_type: 이벤트 유형
            description: 이벤트 설명
            severity: 심각도 (INFO, WARNING, ERROR, CRITICAL)
            details: 추가 세부사항
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "description": description,
            "severity": severity,
            "details": details or {}
        }
        
        # 심각도에 따라 다른 로그 레벨 사용
        if severity == "CRITICAL":
            self.audit_logger.critical(json.dumps(log_entry, ensure_ascii=False))
        elif severity == "ERROR":
            self.audit_logger.error(json.dumps(log_entry, ensure_ascii=False))
        elif severity == "WARNING":
            self.audit_logger.warning(json.dumps(log_entry, ensure_ascii=False))
        else:
            self.audit_logger.info(json.dumps(log_entry, ensure_ascii=False))


def secure_tool(
    requires_encryption: bool = False,
    log_access: bool = True,
    pii_policy: str = "encrypt"  # "encrypt", "reject", "mask"
):
    """
    도구를 위한 보안 데코레이터
    
    Args:
        requires_encryption: 암호화 필요 여부
        log_access: 접근 로그 기록 여부
        pii_policy: PII 발견 시 처리 정책
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 보안 서비스 초기화 (전역 인스턴스 사용)
            pii_detector = get_pii_detector()
            encryption_service = get_encryption_service()
            auditor = get_security_auditor()
            
            # 함수 이름과 매개변수 추출
            tool_name = func.__name__
            
            # 매개변수에서 PII 스캔
            pii_found = pii_detector.scan_parameters(kwargs)
            
            # 클라이언트 정보 추출 (가능한 경우)
            client_id = kwargs.get('client_id', 'unknown')
            user_id = kwargs.get('user_id', 'anonymous')
            
            # PII 발견 시 정책에 따라 처리
            action_taken = "executed"
            
            if pii_found:
                security_logger.warning(f"PII 탐지됨 in {tool_name}: {[f'{param}:{pii_type}' for param, pii_type, _ in pii_found]}")
                
                if pii_policy == "reject":
                    action_taken = "rejected_pii"
                    auditor.log_access(
                        tool_name=tool_name,
                        user_id=user_id,
                        client_id=client_id,
                        parameters={k: "***" for k in kwargs.keys()},
                        contains_pii=True,
                        action_taken=action_taken
                    )
                    raise ValueError("요청에 안전하게 처리할 수 없는 민감한 데이터가 포함되어 있습니다")
                
                elif pii_policy == "encrypt" and requires_encryption:
                    action_taken = "executed_with_encryption"
                    for param_name, pii_type, matches in pii_found:
                        # 민감한 매개변수 암호화
                        kwargs[param_name] = encryption_service.encrypt(kwargs[param_name])
                        security_logger.info(f"매개변수 '{param_name}' 암호화됨 ({pii_type})")
                
                elif pii_policy == "mask":
                    action_taken = "executed_with_masking"
                    for param_name, pii_type, matches in pii_found:
                        if isinstance(kwargs[param_name], str):
                            kwargs[param_name] = pii_detector.mask_pii(kwargs[param_name])
            
            # 접근 로그 기록
            if log_access:
                # 매개변수는 마스킹해서 로그에 기록
                masked_params = {}
                for k, v in kwargs.items():
                    if isinstance(v, str):
                        masked_params[k] = pii_detector.mask_pii(v)
                    else:
                        masked_params[k] = "***"
                
                auditor.log_access(
                    tool_name=tool_name,
                    user_id=user_id,
                    client_id=client_id,
                    parameters=masked_params,
                    contains_pii=bool(pii_found),
                    action_taken=action_taken
                )
            
            # 원래 함수 실행
            try:
                result = await func(*args, **kwargs)
                
                # 결과에서도 PII 검사 (필요한 경우)
                if isinstance(result, dict) and pii_found and requires_encryption:
                    # 결과를 암호화해서 반환할 수도 있음
                    pass
                
                return result
                
            except Exception as e:
                # 실행 오류 로그
                auditor.log_security_event(
                    event_type="tool_execution_error",
                    description=f"도구 {tool_name} 실행 중 오류",
                    severity="ERROR",
                    details={"error": str(e), "tool_name": tool_name}
                )
                raise
        
        return wrapper
    return decorator


# 전역 보안 서비스 인스턴스
_pii_detector = None
_encryption_service = None
_security_auditor = None


def get_pii_detector() -> PiiDetector:
    """글로벌 PII 탐지기 인스턴스 반환"""
    global _pii_detector
    # 패턴 파일이 업데이트될 수 있으므로 항상 새로운 인스턴스 생성
        _pii_detector = PiiDetector()
    return _pii_detector


def get_encryption_service() -> EncryptionService:
    """글로벌 암호화 서비스 인스턴스 반환"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


def get_security_auditor() -> SecurityAuditor:
    """글로벌 보안 감사자 인스턴스 반환"""
    global _security_auditor
    if _security_auditor is None:
        _security_auditor = SecurityAuditor()
    return _security_auditor 