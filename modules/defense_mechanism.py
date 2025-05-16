#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
방어 메커니즘 모듈 - IDS 시스템의 공격 대응 기능을 제공

이 모듈은 침입 탐지 시스템에서 악의적인 트래픽을 차단하고,
관리자에게 알림을 보내며, 자동 방어 기능을 제공합니다.
"""
import os
import sys
import time
import socket
import logging
import subprocess
import smtplib
import json
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# 수리카타 매니저 추가 시도
try:
    from .suricata_manager import SuricataManager
    SURICATA_SUPPORT = True
except ImportError:
    SURICATA_SUPPORT = False

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("defense_actions.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DefenseMechanism")

class DefenseManager:
    """방어 메커니즘 통합 관리 클래스"""
    
    def __init__(self, config_file=None, mode="lightweight"):
        """방어 메커니즘 초기화
        
        Args:
            config_file (str): 설정 파일 경로
            mode (str): 운영 모드 ('lightweight' 또는 'performance')
        """
        self.mode = mode
        self.blocker = BlockMaliciousTraffic()
        self.alert_system = AlertSystem(config_file)
        self.auto_defense = AutoDefenseActions()
        self.is_active = True
        self.recent_threats = []
        self.thread_lock = threading.Lock()
        
        # 수리카타 관련 속성
        self.suricata_manager = None
        self.suricata_enabled = False
        
        # 설정 파일 로드
        self.config = self._load_config(config_file)
        
        # 모드에 따른 초기화
        self._initialize_by_mode()
        
        logger.info(f"방어 메커니즘 관리자 초기화 완료 (모드: {self.mode})")
    
    def _initialize_by_mode(self):
        """현재 모드에 따른 초기화 수행"""
        if self.mode == "performance":
            if SURICATA_SUPPORT:
                try:
                    self.suricata_manager = SuricataManager()
                    self.suricata_manager.initialize()
                    self.suricata_enabled = True
                    logger.info("수리카타 통합 모듈 초기화 완료")
                except Exception as e:
                    logger.error(f"수리카타 초기화 실패: {e} - 경량 모드로 전환합니다.")
                    self.mode = "lightweight"
                    self.suricata_enabled = False
            else:
                logger.warning("수리카타 지원 모듈을 찾을 수 없습니다. 경량 모드로 전환합니다.")
                self.mode = "lightweight"
        else:
            logger.info("경량 모드로 실행 중입니다.")
    
    def switch_mode(self, new_mode):
        """운영 모드 전환
        
        Args:
            new_mode (str): 새 운영 모드 ('lightweight' 또는 'performance')
            
        Returns:
            bool: 모드 전환 성공 여부
        """
        if new_mode == self.mode:
            logger.info(f"이미 {new_mode} 모드로 실행 중입니다.")
            return True
            
        logger.info(f"{self.mode} 모드에서 {new_mode} 모드로 전환 시도 중...")
        
        if new_mode == "performance":
            # 경량 → 고성능 모드 전환
            if not SURICATA_SUPPORT:
                logger.error("수리카타 지원 모듈이 설치되지 않았습니다. 모드 전환 실패.")
                return False
                
            try:
                if not self.suricata_manager:
                    self.suricata_manager = SuricataManager()
                    
                self.suricata_manager.initialize()
                self.suricata_enabled = True
                self.mode = "performance"
                logger.info("고성능 모드로 성공적으로 전환되었습니다.")
                return True
            except Exception as e:
                logger.error(f"고성능 모드 전환 실패: {e}")
                return False
        else:
            # 고성능 → 경량 모드 전환
            if self.suricata_manager and self.suricata_enabled:
                try:
                    self.suricata_manager.shutdown()
                    self.suricata_enabled = False
                except Exception as e:
                    logger.warning(f"수리카타 종료 중 경고: {e}")
                    
            self.mode = "lightweight"
            logger.info("경량 모드로 성공적으로 전환되었습니다.")
            return True
        
    def _load_config(self, config_file):
        """설정 파일 로드"""
        default_config = {
            "defense": {
                "auto_block": True,
                "block_duration": 1800,
                "high_threat_threshold": 0.9,
                "medium_threat_threshold": 0.8,
                "low_threat_threshold": 0.7
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # 기본 설정과 병합
                    if "defense" in config:
                        default_config["defense"].update(config["defense"])
                logger.info(f"설정 파일 로드됨: {config_file}")
            except Exception as e:
                logger.error(f"설정 파일 로드 오류: {str(e)}")
        
        return default_config
    
    def handle_packet(self, packet_info):
        """
        패킷 캡처 모듈로부터 직접 패킷을 전달받아 처리하는 콜백 함수
        
        Args:
            packet_info (dict): 캡처된 패킷 정보
        """
        if not self.is_active:
            return
        
        try:
            with self.thread_lock:  # 스레드 안전성 보장
                # 기본 분석 수행
                prediction, confidence = self.auto_defense.analyze_packet(packet_info)
                
                # 고성능 모드에서 수리카타 분석 추가
                if self.mode == "performance" and self.suricata_enabled and self.suricata_manager:
                    suricata_result = self.suricata_manager.check_packet(packet_info)
                    if suricata_result:
                        # 수리카타 결과로 예측 및 신뢰도 보강
                        prediction = 1  # 수리카타가 경고를 발생시켰으므로 위협으로 표시
                        suricata_confidence = suricata_result.get('suricata_confidence', 0.8)
                        
                        # 기존 신뢰도와 수리카타 신뢰도 중 높은 값 사용
                        confidence = max(confidence, suricata_confidence)
                        
                        # 패킷 정보에 수리카타 결과 추가
                        packet_info.update(suricata_result)
                        
                        logger.info(f"수리카타 경고 감지: {suricata_result.get('suricata_signature', '알 수 없음')}, "
                                   f"신뢰도: {suricata_confidence:.2f}")
                
                # 위협으로 탐지된 경우 방어 조치
                if prediction == 1 and confidence >= self.config["defense"]["medium_threat_threshold"]:
                    source_ip = packet_info.get('source', '').split(':')[0] if ':' in packet_info.get('source', '') else packet_info.get('source', '')
                    
                    # 중복 대응 방지 (같은 IP에 대한 연속 대응 제한)
                    if self._check_recent_threat(source_ip):
                        logger.info(f"중복 위협 무시: {source_ip} (최근에 이미 대응함)")
                        return
                    
                    # 수리카타 경고가 있는 경우 추가 정보 출력
                    if 'suricata_alert' in packet_info and packet_info['suricata_alert']:
                        print(f"\n[경고] 수리카타 시그니처 탐지: {packet_info.get('suricata_signature', '알 수 없음')}")
                        print(f"출발지: {source_ip}, 카테고리: {packet_info.get('suricata_category', '알 수 없음')}")
                    else:
                        print(f"\n[경고] 잠재적 공격 탐지: {source_ip} (신뢰도: {confidence:.2f})")
                    
                    # 위협 수준에 따른 대응
                    self.auto_defense.execute_defense_action(packet_info, confidence)
                    
                    # 최근 위협 목록에 추가
                    self._add_recent_threat(source_ip)
                    
                    logger.info(f"패킷 처리 완료: {source_ip} (신뢰도: {confidence:.2f})")
        except Exception as e:
            logger.error(f"패킷 처리 중 오류 발생: {str(e)}")
    
    def _check_recent_threat(self, ip_address):
        """최근 위협 목록에 IP가 있는지 확인"""
        # 5초 이내의 중복 처리 방지
        current_time = time.time()
        for threat in self.recent_threats[:]:
            # 오래된 항목 제거
            if current_time - threat["timestamp"] > 5:
                self.recent_threats.remove(threat)
            elif threat["ip"] == ip_address:
                return True
        return False
    
    def _add_recent_threat(self, ip_address):
        """최근 위협 목록에 IP 추가"""
        self.recent_threats.append({
            "ip": ip_address,
            "timestamp": time.time()
        })
        # 목록 크기 제한
        if len(self.recent_threats) > 100:
            self.recent_threats.pop(0)
    
    def register_to_packet_capture(self, packet_capture_core):
        """패킷 캡처 코어에 콜백 함수 등록"""
        if packet_capture_core:
            result = packet_capture_core.register_defense_module(self.handle_packet)
            
            # 고성능 모드인 경우 수리카타 모니터링 시작
            if result and self.mode == "performance" and self.suricata_enabled and self.suricata_manager:
                # 패킷 캡처와 동일한 인터페이스에서 수리카타 모니터링 시작
                interface = packet_capture_core.get_active_interface()
                if interface:
                    self.suricata_manager.start_monitoring(interface)
                    logger.info(f"수리카타 모니터링 시작: 인터페이스 {interface}")
            
            return result
        return False
    
    def activate(self):
        """방어 메커니즘 활성화"""
        self.is_active = True
        logger.info("방어 메커니즘 활성화됨")
    
    def deactivate(self):
        """방어 메커니즘 비활성화"""
        self.is_active = False
        # 수리카타 모니터링 중지
        if self.suricata_enabled and self.suricata_manager:
            self.suricata_manager.stop_monitoring()
        logger.info("방어 메커니즘 비활성화됨")
    
    def get_status(self):
        """방어 메커니즘 상태 반환"""
        status = {
            "is_active": self.is_active,
            "mode": self.mode,
            "blocked_ips": self.blocker.get_blocked_ips(),
            "alert_enabled": self.alert_system.email_config["enabled"],
            "config": self.config
        }
        
        # 수리카타 관련 상태 추가
        if self.mode == "performance":
            status["suricata_enabled"] = self.suricata_enabled
            if self.suricata_enabled and self.suricata_manager:
                status["suricata_running"] = self.suricata_manager.is_running
        
        return status
    
    def shutdown(self):
        """방어 메커니즘 종료"""
        self.deactivate()
        if self.suricata_enabled and self.suricata_manager:
            self.suricata_manager.shutdown()
        logger.info("방어 메커니즘 종료됨")


class BlockMaliciousTraffic:
    """악의적인 트래픽 차단을 위한 클래스"""
    
    def __init__(self):
        """방화벽 규칙 관리를 위한 초기화"""
        self.blocked_ips = set()
        self.block_history = []
        self.os_type = os.name
        logger.info("트래픽 차단 시스템 초기화 완료")
    
    def block_ip(self, ip_address):
        """
        악의적인 IP 주소를 방화벽에서 차단     
        Args:
            ip_address (str): 차단할 IP 주소
        Returns:
            bool: 차단 성공 여부
        """
        if not self._is_valid_ip(ip_address):
            logger.error(f"유효하지 않은 IP 주소: {ip_address}")
            return False
        if ip_address in self.blocked_ips:
            logger.info(f"이미 차단된 IP 주소: {ip_address}")
            return True
        try:
            # OS별 방화벽 명령어 실행
            if self.os_type == 'nt':  # Windows
                result = self._block_ip_windows(ip_address)
            else:  # Linux/Unix
                result = self._block_ip_linux(ip_address)
            if result:
                self.blocked_ips.add(ip_address)
                block_event = {
                    "ip": ip_address,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "success": True
                }
                self.block_history.append(block_event)
                self._save_block_history()
                logger.info(f"IP 주소 차단 성공: {ip_address}")
                return True
            else:
                logger.error(f"IP 주소 차단 실패: {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"IP 차단 중 오류 발생: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        차단된 IP 주소를 방화벽에서 해제
        
        Args:
            ip_address (str): 해제할 IP 주소
            
        Returns:
            bool: 해제 성공 여부
        """
        if not self._is_valid_ip(ip_address):
            logger.error(f"유효하지 않은 IP 주소: {ip_address}")
            return False
        
        if ip_address not in self.blocked_ips:
            logger.info(f"차단되지 않은 IP 주소: {ip_address}")
            return True
        
        try:
            # OS별 방화벽 명령어 실행
            if self.os_type == 'nt':  # Windows
                result = self._unblock_ip_windows(ip_address)
            else:  # Linux/Unix
                result = self._unblock_ip_linux(ip_address)
            
            if result:
                self.blocked_ips.remove(ip_address)
                unblock_event = {
                    "ip": ip_address,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "action": "unblock",
                    "success": True
                }
                self.block_history.append(unblock_event)
                self._save_block_history()
                logger.info(f"IP 주소 차단 해제 성공: {ip_address}")
                return True
            else:
                logger.error(f"IP 주소 차단 해제 실패: {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"IP 차단 해제 중 오류 발생: {str(e)}")
            return False
    
    def get_blocked_ips(self):
        """
        현재 차단된 IP 주소 목록 반환
        
        Returns:
            list: 차단된 IP 주소 목록
        """
        return list(self.blocked_ips)
    
    def _block_ip_windows(self, ip_address):
        """Windows 방화벽에서 IP 차단"""
        try:
            rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
            command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Windows IP 차단 중 오류: {str(e)}")
            return False
    
    def _unblock_ip_windows(self, ip_address):
        """Windows 방화벽에서 IP 차단 해제"""
        try:
            rule_name = f"IDS_Block_{ip_address.replace('.', '_')}"
            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Windows IP 차단 해제 중 오류: {str(e)}")
            return False
    
    def _block_ip_linux(self, ip_address):
        """Linux 방화벽(iptables)에서 IP 차단"""
        try:
            command = f'iptables -A INPUT -s {ip_address} -j DROP'
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Linux IP 차단 중 오류: {str(e)}")
            return False
    
    def _unblock_ip_linux(self, ip_address):
        """Linux 방화벽(iptables)에서 IP 차단 해제"""
        try:
            command = f'iptables -D INPUT -s {ip_address} -j DROP'
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Linux IP 차단 해제 중 오류: {str(e)}")
            return False
    
    def _is_valid_ip(self, ip_address):
        """IP 주소 유효성 검사"""
        try:
            socket.inet_aton(ip_address)
            return True
        except:
            return False
    
    def _save_block_history(self):
        """차단 기록 저장"""
        try:
            with open('blocked_ips_history.json', 'w') as f:
                json.dump(self.block_history, f, indent=4)
        except Exception as e:
            logger.error(f"차단 기록 저장 중 오류: {str(e)}")
            
class AlertSystem:
    """관리자에게 알림을 보내는 시스템"""
    def __init__(self, config_file=None):
        """알림 시스템 초기화"""
        self.alerts = []
        self.email_config = {
            "enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "recipient": ""
        }
        
        # 설정 파일이 있으면 로드
        if config_file and os.path.exists(config_file):
            self._load_config(config_file)
        
        logger.info("알림 시스템 초기화 완료")
    
    def send_alert(self, alert_info):
        """
        경고 알림 발송
        
        Args:
            alert_info (dict): 알림 정보 (소스 IP, 타임스탬프, 프로토콜 등)
        
        Returns:
            bool: 알림 발송 성공 여부
        """
        try:
            # 콘솔에 경고 출력
            alert_text = self._format_alert(alert_info)
            print("\n" + "!"*50)
            print(alert_text)
            print("!"*50)
            
            # 알림 기록 저장
            self.alerts.append(alert_info)
            self._save_alerts()
            
            # 이메일 알림 설정이 활성화된 경우 이메일 발송
            if self.email_config["enabled"]:
                self._send_email_alert(alert_info)
            
            logger.info(f"알림 발송 성공: {alert_info['source_ip']}")
            return True
            
        except Exception as e:
            logger.error(f"알림 발송 중 오류: {str(e)}")
            return False
    
    def _format_alert(self, alert_info):
        """알림 정보 서식화"""
        alert_text = f"[보안 경고] 잠재적 공격 탐지\n"
        alert_text += f"시간: {alert_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
        alert_text += f"출발지 IP: {alert_info.get('source_ip', 'Unknown')}\n"
        alert_text += f"프로토콜: {alert_info.get('protocol', 'Unknown')}\n"
        alert_text += f"신뢰도: {alert_info.get('confidence', 0):.2f}\n"
        alert_text += f"취한 조치: {alert_info.get('action_taken', '없음')}"
        return alert_text
    
    def _send_email_alert(self, alert_info):
        """이메일로 알림 발송"""
        try:
            if not all([
                self.email_config["smtp_server"],
                self.email_config["username"],
                self.email_config["password"],
                self.email_config["recipient"]
            ]):
                logger.error("이메일 설정이 완료되지 않았습니다.")
                return False
            
            # 이메일 메시지 생성
            msg = MIMEMultipart()
            msg['From'] = self.email_config["username"]
            msg['To'] = self.email_config["recipient"]
            msg['Subject'] = f"[IDS 경고] 잠재적 공격 탐지 - {alert_info.get('source_ip', 'Unknown')}"
            
            body = self._format_alert(alert_info)
            msg.attach(MIMEText(body, 'plain'))
            
            # SMTP 서버로 이메일 발송
            with smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"]) as server:
                server.starttls()
                server.login(self.email_config["username"], self.email_config["password"])
                server.send_message(msg)
            
            logger.info(f"이메일 알림 발송 성공: {self.email_config['recipient']}")
            return True
            
        except Exception as e:
            logger.error(f"이메일 알림 발송 중 오류: {str(e)}")
            return False
    
    def _save_alerts(self):
        """알림 기록 저장"""
        try:
            with open('security_alerts.json', 'w') as f:
                json.dump(self.alerts, f, indent=4)
        except Exception as e:
            logger.error(f"알림 기록 저장 중 오류: {str(e)}")
    
    def _load_config(self, config_file):
        """설정 파일에서 알림 설정 로드"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                if "email" in config:
                    self.email_config.update(config["email"])
                    if all([
                        self.email_config["smtp_server"],
                        self.email_config["username"],
                        self.email_config["password"],
                        self.email_config["recipient"]
                    ]):
                        self.email_config["enabled"] = True
        except Exception as e:
            logger.error(f"설정 파일 로드 중 오류: {str(e)}")


class AutoDefenseActions:
    """위협 수준에 따른 자동 방어 조치 실행"""
    
    def __init__(self):
        """자동 방어 시스템 초기화"""
        self.action_history = []
        self.is_enabled = True
        self.blocker = BlockMaliciousTraffic()  # 내부적으로 IP 차단 객체 사용
        self.alert_system = AlertSystem()  # 내부적으로 알림 시스템 사용
        logger.info("자동 방어 시스템 초기화 완료")
    
    def analyze_packet(self, packet):
        """
        패킷 분석 및 위협 예측
        
        Args:
            packet (dict): 분석할 패킷 정보
            
        Returns:
            tuple: (예측 결과, 신뢰도) - 1=공격, 0=정상
        """
        try:
            # 1. 기본 휴리스틱 검사
            if self._check_basic_heuristics(packet):
                return 1, 0.95
            
            # 간단한 휴리스틱 검사 결과 반환
            protocol = str(packet.get('protocol', '')).lower()
            info = str(packet.get('info', '')).lower()
            
            # 프로토콜 번호를 문자열로 변환
            if protocol == '6':  # TCP
                protocol = 'tcp'
            elif protocol == '17':  # UDP
                protocol = 'udp'
            elif protocol == '1':  # ICMP
                protocol = 'icmp'
            
            if 'syn' in info and protocol == 'tcp':
                return 1, 0.85  # SYN 플러딩 의심
            elif protocol == 'icmp' and packet.get('length', 0) > 1000:
                return 1, 0.9   # ICMP 플러딩 의심
            
            # 다른 특별한 패턴이 없으면 정상으로 판단
            return 0, 0.7
            
        except Exception as e:
            logger.error(f"패킷 분석 중 오류: {str(e)}")
            return 0, 0.5  # 오류 발생 시 기본값 반환
    
    def execute_defense_action(self, packet, confidence):
        """
        위협 수준에 따른 방어 조치 실행
        
        Args:
            packet (dict): 패킷 정보
            confidence (float): 위협 감지 신뢰도 (0.0 ~ 1.0)
            
        Returns:
            bool: 방어 조치 실행 성공 여부
        """
        if not self.is_enabled:
            logger.info("자동 방어 시스템이 비활성화 되어 있습니다.")
            return False
        
        try:
            source_ip = packet.get('source', '').split(':')[0] if ':' in packet.get('source', '') else packet.get('source', '')
            protocol = packet.get('protocol', '')
            
            # 프로토콜 번호를 이름으로 변환
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            if isinstance(protocol, int) or protocol.isdigit():
                protocol = protocol_map.get(int(protocol), str(protocol))
            
            # 위협 수준에 따른 대응
            if confidence >= 0.9:  # 매우 높은 위협
                action = "높은_위협_차단"
                self._high_threat_response(source_ip, protocol)
            elif confidence >= 0.8:  # 높은 위협
                action = "중간_위협_차단"
                self._medium_threat_response(source_ip, protocol)
            elif confidence >= 0.7:  # 중간 위협
                action = "낮은_위협_모니터링"
                self._low_threat_response(source_ip, protocol)
            else:  # 낮은 위협
                action = "모니터링만"
                self._monitoring_only(source_ip)
            
            # 방어 조치 기록
            action_record = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": source_ip,
                "protocol": protocol,
                "confidence": confidence,
                "action": action
            }
            self.action_history.append(action_record)
            self._save_action_history()
            
            logger.info(f"방어 조치 실행: {action} - {source_ip}")
            return True
            
        except Exception as e:
            logger.error(f"방어 조치 실행 중 오류: {str(e)}")
            return False
    
    def _high_threat_response(self, ip, protocol):
        """매우 높은 위협에 대한 대응"""
        try:
            # 1. IP 차단
            self.blocker.block_ip(ip)
            
            # 2. 관리자에게 긴급 알림
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.95,
                "action_taken": "IP 영구 차단 및 긴급 알림"
            }
            self.alert_system.send_alert(alert_info)
            
            # 3. 추가적인 보안 강화 조치 (예: 특정 포트 일시적 차단 등)
            logger.info(f"매우 높은 위협 대응 완료: {ip}")
            
        except Exception as e:
            logger.error(f"높은 위협 대응 중 오류: {str(e)}")
    
    def _medium_threat_response(self, ip, protocol):
        """높은 위협에 대한 대응"""
        try:
            # 1. 임시 IP 차단 (30분)
            self.blocker.block_ip(ip)
            
            # 일정 시간 후 자동 해제를 위한 스레드 (실제 구현 시)
            def unblock_later():
                time.sleep(1800)  # 30분
                self.blocker.unblock_ip(ip)
                logger.info(f"IP 차단 자동 해제: {ip}")
            
            threading.Thread(target=unblock_later, daemon=True).start()
            
            # 2. 관리자에게 알림
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.85,
                "action_taken": "IP 임시 차단 (30분)"
            }
            self.alert_system.send_alert(alert_info)
            
            logger.info(f"중간 위협 대응 완료: {ip}")
            
        except Exception as e:
            logger.error(f"중간 위협 대응 중 오류: {str(e)}")
    
    def _low_threat_response(self, ip, protocol):
        """중간 위협에 대한 대응"""
        try:
            # 패킷 제한 및 모니터링 강화
            logger.info(f"낮은 위협 감지: {ip} - 모니터링 강화")
            
            # 알림 전송
            alert_info = {
                "source_ip": ip,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "protocol": protocol,
                "confidence": 0.75,
                "action_taken": "모니터링 강화"
            }
            self.alert_system.send_alert(alert_info)
            
        except Exception as e:
            logger.error(f"낮은 위협 대응 중 오류: {str(e)}")
    
    def _monitoring_only(self, ip):
        """낮은 위협에 대한 대응 (모니터링만)"""
        logger.info(f"의심 활동 모니터링: {ip}")
    
    def _check_basic_heuristics(self, packet):
        """기본적인 휴리스틱 검사"""
        try:
            info = str(packet.get('info', '')).lower()
            protocol = str(packet.get('protocol', '')).lower()
            
            # 프로토콜 번호를 문자열로 변환
            if protocol == '6':  # TCP
                protocol = 'tcp'
            elif protocol == '17':  # UDP
                protocol = 'udp'
            elif protocol == '1':  # ICMP
                protocol = 'icmp'
            
            # 1. SYN 플러딩 검사
            if ('tcp' in protocol or protocol == '6') and 'syn' in info:
                # 실제 구현에서는 짧은 시간 내 다수의 SYN 패킷 검사 필요
                return True
            
            # 2. 비정상적인 패킷 크기
            if packet.get('length', 0) > 5000:
                return True
            
            # 3. 알려진 악성 포트 확인
            dest = packet.get('destination', '')
            if ':' in dest:
                try:
                    port = int(dest.split(':')[1])
                    if port in [4444, 31337, 1337]:  # 잘 알려진 악성 포트 예시
                        return True
                except:
                    pass
            
            return False
            
        except Exception as e:
            logger.error(f"휴리스틱 검사 중 오류: {str(e)}")
            return False
    
    def _save_action_history(self):
        """방어 조치 기록 저장"""
        try:
            with open('defense_actions_history.json', 'w') as f:
                json.dump(self.action_history, f, indent=4)
        except Exception as e:
            logger.error(f"방어 조치 기록 저장 중 오류: {str(e)}")

# 모듈 내보내기용 함수
def create_defense_manager(config_file='defense_config.json', mode="lightweight"):
    """방어 메커니즘 관리자 생성"""
    return DefenseManager(config_file, mode=mode)

def register_to_packet_capture(defense_manager, packet_capture_core):
    """패킷 캡처 코어에 방어 메커니즘 등록"""
    return defense_manager.register_to_packet_capture(packet_capture_core)

if __name__ == "__main__":
    # 모듈 테스트 코드
    print("방어 메커니즘 모듈 테스트")
    
    # 방어 관리자 생성
    defense_manager = create_defense_manager()
    
    # 테스트 패킷 생성
    test_packet = {
        "source": "192.168.1.100:1234",
        "destination": "192.168.1.1:80",
        "protocol": "TCP",
        "length": 60,
        "info": "SYN"
    }
    
    # 패킷 분석 및 방어 조치 테스트
    defense_manager.handle_packet(test_packet)
    
    print("방어 메커니즘 테스트 완료") 