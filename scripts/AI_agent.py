import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import socket
import time
import os
import random
import ctypes
import sys
from datetime import datetime
import threading
import queue
import winreg
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# 운영체제에 따른 모듈 임포트
if os.name == 'nt':  # Windows
    import msvcrt
else:  # Linux/Mac
    import termios
    import tty

# Colab 환경이 아닐 때만 scapy 임포트
if not os.path.exists('/content'):
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.sendrecv import sr1, send
    except ImportError:
        print("scapy 라이브러리가 설치되어 있지 않습니다.")
        print("설치하려면: pip install scapy")
        sys.exit(1)

def is_colab():
    """
    Google Colab 환경인지 확인
    """
    return os.path.exists('/content')

def is_admin():
    """
    Windows에서 관리자 권한 확인
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """
    관리자 권한으로 프로그램 재실행
    """
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def clear_screen():
    """
    화면 지우기
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_for_enter():
    """
    Enter 키를 누를 때까지 대기
    """
    print("\n계속하려면 Enter 키를 누르세요...")
    
    if os.name == 'nt':  # Windows
        while True:
            if msvcrt.kbhit():
                if msvcrt.getch() == b'\r':  # Enter 키
                    break
    else:  # Linux/Mac
        # 터미널 설정 저장
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            while True:
                if sys.stdin.read(1) == '\n':  # Enter 키
                    break
        finally:
            # 터미널 설정 복원
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

def print_scan_status(port, status, start_time):
    """
    스캔 상태를 실시간으로 출력
    """
    elapsed_time = time.time() - start_time
    current_time = datetime.now().strftime("%H:%M:%S")
    
    status_colors = {
        'open': '\033[92m',    # 녹색
        'closed': '\033[91m',  # 빨간색
        'filtered': '\033[93m' # 노란색
    }
    
    color = status_colors.get(status, '\033[0m')
    reset = '\033[0m'
    
    print(f"\r[{current_time}] 포트 {port}: {color}{status}{reset} | 경과 시간: {elapsed_time:.1f}초", end='', flush=True)

def syn_scan(target_ip, ports):
    """
    TCP SYN 스캔을 수행하는 함수
    """
    if is_colab():
        print("Google Colab 환경에서는 포트 스캔 기능을 사용할 수 없습니다.")
        return None

    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    start_time = time.time()
    total_ports = len(ports)
    
    print(f"\n대상 IP: {target_ip}")
    print(f"스캔할 포트 수: {total_ports}")
    print("=" * 50)
    
    for i, port in enumerate(ports, 1):
        # 랜덤 소스 포트 생성
        src_port = random.randint(1024, 65535)
        
        # SYN 패킷 생성
        ip_packet = IP(dst=target_ip)
        tcp_packet = TCP(sport=src_port, dport=port, flags="S")
        packet = ip_packet/tcp_packet
        
        try:
            # 패킷 전송 및 응답 대기
            response = sr1(packet, timeout=1, verbose=0)
            
            if response is None:
                filtered_ports.append(port)
                print_scan_status(port, "filtered", start_time)
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK 응답
                    open_ports.append(port)
                    print_scan_status(port, "open", start_time)
                    # RST 패킷 전송하여 연결 종료
                    rst_packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
                    send(rst_packet, verbose=0)
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK 응답
                    closed_ports.append(port)
                    print_scan_status(port, "closed", start_time)
        except Exception as e:
            print(f"\r포트 {port} 스캔 중 오류 발생: {str(e)}")
            continue
            
        time.sleep(0.1)  # 연속 스캔 방지
    
    print("\n" + "=" * 50)
    print(f"\n스캔 완료! 총 소요 시간: {time.time() - start_time:.1f}초")
    
    return {
        'open': open_ports,
        'closed': closed_ports,
        'filtered': filtered_ports
    }

# 패킷 캡처 관련 클래스들
class PacketCapture:
    def __init__(self, interface, count=100):
        self.interface = interface
        self.count = count

    def capture_packets(self):
        """지정된 네트워크 인터페이스에서 패킷을 캡처합니다."""
        return sniff(iface=self.interface, count=self.count)

    def preprocess_packets(self, packets):
        """캡처된 패킷을 DataFrame으로 전처리합니다."""
        data = []
        for packet in packets:
            if IP in packet:
                data.append({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'info': self._get_packet_info(packet)
                })
        return pd.DataFrame(data)

    def _get_packet_info(self, packet):
        """패킷 정보 추출"""
        info = []
        if IP in packet:
            info.append(f"IP {packet[IP].src} → {packet[IP].dst}")
            info.append(f"TTL: {packet[IP].ttl}")
            info.append(f"ID: {packet[IP].id}")
            if TCP in packet:
                info.append(f"TCP {packet[TCP].sport} → {packet[TCP].dport}")
                info.append(f"Seq: {packet[TCP].seq}")
                info.append(f"Ack: {packet[TCP].ack}")
                info.append(f"Window: {packet[TCP].window}")
                flags = self._get_tcp_flags(packet[TCP].flags)
                if flags:
                    info.append(f"Flags: {' '.join(flags)}")
            elif UDP in packet:
                info.append(f"UDP {packet[UDP].sport} → {packet[UDP].dport}")
                info.append(f"Length: {packet[UDP].len}")
            elif ICMP in packet:
                info.append(f"ICMP Type: {packet[ICMP].type}")
                info.append(f"ICMP Code: {packet[ICMP].code}")
        return ' | '.join(info)

    def _get_tcp_flags(self, flags):
        """TCP 플래그 추출"""
        flag_list = []
        if flags & 0x02:  # SYN
            flag_list.append("SYN")
        if flags & 0x10:  # ACK
            flag_list.append("ACK")
        if flags & 0x01:  # FIN
            flag_list.append("FIN")
        if flags & 0x04:  # RST
            flag_list.append("RST")
        if flags & 0x08:  # PSH
            flag_list.append("PSH")
        if flags & 0x20:  # URG
            flag_list.append("URG")
        return flag_list

    def save_to_csv(self, dataframe, filename):
        """DataFrame을 CSV 파일로 저장합니다."""
        if not os.path.exists('data'):
            os.makedirs('data')
        filepath = os.path.join('data', filename)
        try:
            dataframe.to_csv(filepath, index=False)
            print(f"데이터가 {filepath}에 저장되었습니다.")
        except Exception as e:
            print(f"데이터 저장 중 오류 발생: {e}")

class PacketCaptureCore:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=100)
        self.is_running = False
        self.packet_count = 0
        self.max_packets = 300000
        self.sniff_thread = None
        self.capture_completed = False

    def check_npcap(self):
        """Npcap 설치 여부를 확인합니다."""
        # 윈도우 환경이 아닌 경우 Npcap 확인 불필요
        if os.name != 'nt':
            print("윈도우 환경이 아니므로 Npcap 확인을 건너뜁니다.")
            return True
            
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\Npcap")
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Npcap')
            winreg.CloseKey(key)
            print("Npcap detected in registry: SOFTWARE\\WOW6432Node\\Npcap")
            return True
        except FileNotFoundError:
            print("Npcap not found in registry: SOFTWARE\\WOW6432Node\\Npcap")
        default_path = os.path.join(os.environ.get('SystemRoot', 'C:\Windows'), 'System32', 'Npcap')
        if os.path.exists(default_path):
            print(f"Npcap detected in directory: {default_path}")
            return True
        else:
            print(f"Npcap not found in directory: {default_path}")
        return False

    def get_network_interfaces(self):
        """네트워크 인터페이스 목록을 반환합니다."""
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())

    def start_capture(self, interface, max_packets):
        """패킷 캡처를 시작합니다."""
        if self.is_running:
            return False
        self.is_running = True
        self.packet_count = 0
        self.max_packets = max_packets
        print(f"Starting packet capture on interface: {interface} with max_packets: {max_packets}")
        
        def packet_callback(packet):
            """패킷 캡처 콜백 함수"""
            if not self.is_running:
                return False
            if IP in packet:
                try:
                    packet_info = {
                        'no': self.packet_count + 1,
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': packet[IP].proto,
                        'length': len(packet),
                        'info': str(packet.summary())
                    }
                    self.packet_queue.put(packet_info)
                    self.packet_count += 1
                    print(f"디버그: 패킷 캡처됨 - {self.packet_count}번째 패킷")
                except Exception as e:
                    print(f"디버그: 패킷 처리 중 오류 발생: {str(e)}")
            return True
        
        def capture():
            try:
                print(f"디버그: 캡처 스레드 시작 - 인터페이스: {interface}")
                sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda x: not self.is_running)
                print("디버그: 캡처 스레드 종료")
            except Exception as e:
                print(f"디버그: 캡처 중 오류 발생: {str(e)}")
            finally:
                self.is_running = False
                self.capture_completed = True
        
        self.sniff_thread = threading.Thread(target=capture)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        return True

    def _process_packet(self, packet):
        """캡처된 패킷을 처리합니다."""
        if self.packet_count >= self.max_packets:
            self.is_running = False
            return
        if IP in packet:
            packet_info = {
                'no': self.packet_count + 1,
                'source': packet[IP].src,
                'destination': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'info': str(packet.summary())
            }
            self.packet_queue.put(packet_info)
            self.packet_count += 1

    def get_packet_queue(self):
        """패킷 큐를 반환합니다."""
        return self.packet_queue

    def get_packet_count(self):
        """캡처된 패킷 수를 반환합니다."""
        return self.packet_count

    def stop_capture(self):
        """패킷 캡처를 중지하고 캡처된 패킷 수를 반환합니다."""
        print("Stopping packet capture...")
        self.is_running = False
        if self.sniff_thread is not None:
            self.sniff_thread.join()
        print(f"Packet capture stopped. Total packets captured: {self.packet_count}")
        return self.packet_count

    def get_packet_dataframe(self):
        """패킷 큐에 있는 데이터를 DataFrame으로 변환합니다."""
        packets = []
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            packets.append(packet)
        return pd.DataFrame(packets)

class MLTrainingWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("머신러닝 학습 모니터링")
        self.root.geometry("800x600")
        
        # 상태 표시 영역
        self.status_frame = ttk.LabelFrame(self.root, text="학습 상태", padding=10)
        self.status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="대기 중...")
        self.status_label.pack()
        
        # 로그 표시 영역
        self.log_frame = ttk.LabelFrame(self.root, text="학습 로그", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 성능 지표 표시 영역
        self.metrics_frame = ttk.LabelFrame(self.root, text="성능 지표", padding=10)
        self.metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.accuracy_label = ttk.Label(self.metrics_frame, text="정확도: -")
        self.accuracy_label.pack()
        
        # 혼동 행렬 표시 영역
        self.confusion_frame = ttk.LabelFrame(self.root, text="혼동 행렬", padding=10)
        self.confusion_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.figure = Figure(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.confusion_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # GUI 업데이트를 위한 큐 생성
        self.gui_queue = queue.Queue()
        
        # process_gui_queue 호출
        self.process_gui_queue()

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                task = self.gui_queue.get_nowait()
                if task[0] == 'deiconify':
                    self.root.deiconify()
                elif task[0] == 'update_status':
                    self.status_label.config(text=task[1])
                    self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {task[1]}\n")
                    self.log_text.see(tk.END)
                elif task[0] == 'update_metrics':
                    accuracy = task[1]
                    conf_matrix = task[2]
                    self.accuracy_label.config(text=f"정확도: {accuracy:.4f}")
                    
                    # 혼동 행렬 시각화
                    self.figure.clear()
                    ax = self.figure.add_subplot(111)
                    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', ax=ax)
                    ax.set_xlabel('예측 레이블')
                    ax.set_ylabel('실제 레이블')
                    self.canvas.draw()
        except queue.Empty:
            pass
        self.root.after(100, self.process_gui_queue)  # 100ms마다 큐 확인

    def show(self):
        self.root.mainloop()

def main():
    try:
        # Colab 환경 확인
        if is_colab():
            print("Google Colab 환경에서는 머신러닝 모델 학습만 가능합니다.")
            print("포트 스캔 및 패킷 캡처 기능은 로컬 환경에서만 사용 가능합니다.")
            
            # 데이터 파일이 있는 경우에만 머신러닝 모델 학습 실행
            preprocessed_data_path = 'data_set/전처리데이터1.csv'
            if os.path.exists(preprocessed_data_path):
                print("\n데이터 파일을 찾았습니다. 머신러닝 모델 학습을 시작합니다...")
                # 데이터 로드 및 전처리
                preprocessed_df = pd.read_csv(preprocessed_data_path)
                
                # 문자열 데이터를 숫자로 변환
                for column in preprocessed_df.columns:
                    if preprocessed_df[column].dtype == 'object':
                        # LabelEncoder를 사용하여 문자열을 숫자로 변환
                        label_encoder = LabelEncoder()
                        preprocessed_df[column] = label_encoder.fit_transform(preprocessed_df[column].astype(str))

                # 특성과 레이블 분리
                X = preprocessed_df.drop('protocol_6', axis=1)
                y = preprocessed_df['protocol_6']

                # 데이터 분할
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

                # 데이터 스케일링
                scaler = StandardScaler()
                X_train = scaler.fit_transform(X_train)
                X_test = scaler.transform(X_test)

                # 모델 학습
                model = RandomForestClassifier(n_estimators=100, random_state=42)
                model.fit(X_train, y_train)

                # 모델 평가
                predictions = model.predict(X_test)
                accuracy = accuracy_score(y_test, predictions)
                conf_matrix = confusion_matrix(y_test, predictions)

                print(f'Accuracy: {accuracy}')
                print('Confusion Matrix:')
                print(conf_matrix)

                # 모델 저장
                joblib.dump(model, 'random_forest_model.pkl')
            else:
                print("\n데이터 파일을 찾을 수 없습니다.")
            return

        # 관리자 권한 확인 및 필요시 재실행
        run_as_admin()
        
        # 화면 초기화
        clear_screen()
        
        # 패킷 캡처 코어 초기화
        packet_core = PacketCaptureCore()
        
        # Windows 환경에서만 Npcap 설치 확인
        if os.name == 'nt':
            if not packet_core.check_npcap():
                print("Npcap이 설치되어 있지 않습니다. 패킷 캡처 기능을 사용할 수 없습니다.")
                print("Npcap을 설치한 후 다시 시도해주세요.")
                wait_for_enter()
                return
        
        # 네트워크 인터페이스 목록 가져오기
        interfaces = packet_core.get_network_interfaces()
        
        # 와이파이 인터페이스 찾기
        selected_interface = None
        wifi_keywords = ['wifi', 'wireless', 'wi-fi', 'wlan']
        
        for interface in interfaces:
            interface_lower = interface.lower()
            if any(keyword in interface_lower for keyword in wifi_keywords):
                selected_interface = interface
                break
        
        if not selected_interface:
            print("와이파이 인터페이스를 찾을 수 없습니다.")
            print("사용 가능한 인터페이스 목록:")
            for i, interface in enumerate(interfaces, 1):
                print(f"{i}. {interface}")
            wait_for_enter()
            return
        
        print(f"\n선택된 와이파이 인터페이스: {selected_interface}")
        
        # 백그라운드에서 패킷 캡처 시작
        print(f"\n{selected_interface}에서 패킷 캡처를 시작합니다...")
        if packet_core.start_capture(selected_interface, max_packets=0):  # max_packets=0은 무한 캡처를 의미
            print("패킷 캡처가 백그라운드에서 시작되었습니다.")
            print("프로그램을 종료하려면 Ctrl+C를 누르세요.")
            
            # 실시간 패킷 정보 표시를 위한 스레드
            def display_packet_info():
                last_packet_count = 0
                print("디버그: 패킷 표시 스레드 시작됨")
                while packet_core.is_running:
                    current_count = packet_core.get_packet_count()
                    print(f"디버그: 현재 패킷 수 = {current_count}, 이전 패킷 수 = {last_packet_count}")
                    
                    if current_count > last_packet_count:
                        try:
                            # 최근 캡처된 패킷 정보 가져오기
                            packet = packet_core.packet_queue.get_nowait()
                            print("디버그: 패킷 큐에서 패킷 가져옴")
                            
                            # 패킷 정보 표시
                            print("\n" + "="*50)
                            print(f"캡처된 패킷 수: {current_count}")
                            print(f"시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"출발지: {packet.get('source', 'N/A')}")
                            print(f"목적지: {packet.get('destination', 'N/A')}")
                            print(f"프로토콜: {packet.get('protocol', 'N/A')}")
                            print(f"길이: {packet.get('length', 'N/A')} bytes")
                            print(f"정보: {packet.get('info', 'N/A')}")
                            print("="*50)
                            
                            last_packet_count = current_count
                        except queue.Empty:
                            print("디버그: 패킷 큐가 비어있음")
                            pass
                    time.sleep(0.1)  # CPU 사용량 감소를 위한 짧은 대기
            
            display_thread = threading.Thread(target=display_packet_info)
            display_thread.daemon = True
            display_thread.start()
            
            # 패킷 캡처 상태 모니터링 스레드
            def monitor_capture_status():
                while packet_core.is_running:
                    print(f"\n캡처 상태: {'실행 중' if packet_core.is_running else '중지됨'}")
                    print(f"캡처된 총 패킷 수: {packet_core.get_packet_count()}")
                    print(f"패킷 큐 크기: {packet_core.packet_queue.qsize()}")
                    time.sleep(5)  # 5초마다 상태 업데이트
            
            monitor_thread = threading.Thread(target=monitor_capture_status)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 실시간 패킷 처리 및 저장을 위한 스레드
            def process_and_save_packets():
                packet_buffer = []
                last_save_time = time.time()
                print("디버그: 패킷 처리 및 저장 스레드 시작됨")
                
                while packet_core.is_running:
                    # 패킷 큐에서 패킷 가져오기
                    try:
                        packet = packet_core.packet_queue.get_nowait()
                        packet_buffer.append(packet)
                        print(f"디버그: 패킷 버퍼에 추가됨 - 현재 버퍼 크기: {len(packet_buffer)}")
                    except queue.Empty:
                        pass
                    
                    # 5분마다 또는 버퍼가 1000개 이상일 때 저장
                    current_time = time.time()
                    if len(packet_buffer) >= 1000 or (current_time - last_save_time) >= 300:
                        if packet_buffer:
                            print(f"\n디버그: 패킷 저장 시작 - 버퍼 크기: {len(packet_buffer)}")
                            # DataFrame으로 변환
                            df = pd.DataFrame(packet_buffer)
                            
                            # 데이터 전처리
                            print("디버그: 데이터 전처리 시작")
                            df = preprocess_packet_data(df)
                            print("디버그: 데이터 전처리 완료")
                            
                            # CSV 파일로 저장
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            filename = f"captured_packets_{timestamp}.csv"
                            df.to_csv(filename, index=False)
                            print(f"디버그: 패킷 {len(packet_buffer)}개가 {filename}에 저장됨")
                            
                            # 버퍼 초기화
                            packet_buffer = []
                            last_save_time = current_time
                    
                    time.sleep(0.1)  # CPU 사용량 감소를 위한 짧은 대기
            
            def preprocess_packet_data(df):
                """패킷 데이터 전처리 함수"""
                print("디버그: 전처리 시작 - 입력 데이터 크기:", df.shape)
                
                # 필요한 전처리 작업 수행
                if 'protocol' in df.columns:
                    print("디버그: 프로토콜 매핑 시작")
                    # 프로토콜 번호를 이름으로 매핑
                    protocol_map = {
                        1: 'ICMP',
                        6: 'TCP',
                        17: 'UDP'
                    }
                    df['protocol'] = df['protocol'].map(protocol_map).fillna('Other')
                    print("디버그: 프로토콜 매핑 완료")
                
                if 'source' in df.columns and 'destination' in df.columns:
                    print("디버그: IP 주소 정규화 시작")
                    # IP 주소 정규화
                    df['source'] = df['source'].apply(lambda x: x.split(':')[0] if ':' in x else x)
                    df['destination'] = df['destination'].apply(lambda x: x.split(':')[0] if ':' in x else x)
                    print("디버그: IP 주소 정규화 완료")
                
                print("디버그: 전처리 완료 - 출력 데이터 크기:", df.shape)
                return df
            
            process_thread = threading.Thread(target=process_and_save_packets)
            process_thread.daemon = True
            process_thread.start()
            
            # 머신러닝 학습 창 생성
            ml_window = MLTrainingWindow()
            ml_window.root.withdraw()  # 초기에는 숨겨둠
            
            # 데이터 파일 모니터링 및 머신러닝 모델 학습 스레드 시작
            def monitor_and_train():
                print("디버그: 모니터링 및 학습 스레드 시작됨")
                while packet_core.is_running:
                    preprocessed_data_path = 'data_set/전처리데이터1.csv'
                    if os.path.exists(preprocessed_data_path):
                        # GUI 업데이트는 큐를 통해 요청
                        ml_window.gui_queue.put(('deiconify',))  # 학습 시작 시 창 표시
                        ml_window.gui_queue.put(('update_status', "데이터 파일 감지됨 - 머신러닝 모델 학습 시작"))
                        try:
                            # 데이터 로드 및 전처리
                            ml_window.gui_queue.put(('update_status', "데이터 파일 로드 중..."))
                            preprocessed_df = pd.read_csv(preprocessed_data_path)
                            ml_window.gui_queue.put(('update_status', f"데이터 로드 완료 - 크기: {preprocessed_df.shape}"))
                            
                            # 문자열 데이터를 숫자로 변환
                            ml_window.gui_queue.put(('update_status', "문자열 데이터 변환 시작"))
                            for column in preprocessed_df.columns:
                                if preprocessed_df[column].dtype == 'object':
                                    label_encoder = LabelEncoder()
                                    preprocessed_df[column] = label_encoder.fit_transform(preprocessed_df[column].astype(str))
                            ml_window.gui_queue.put(('update_status', "문자열 데이터 변환 완료"))

                            # 특성과 레이블 분리
                            ml_window.gui_queue.put(('update_status', "특성과 레이블 분리 시작"))
                            X = preprocessed_df.drop('protocol_6', axis=1)
                            y = preprocessed_df['protocol_6']
                            ml_window.gui_queue.put(('update_status', f"특성 크기: {X.shape}, 레이블 크기: {y.shape}"))

                            # 데이터 분할
                            ml_window.gui_queue.put(('update_status', "데이터 분할 시작"))
                            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
                            ml_window.gui_queue.put(('update_status', f"학습 데이터 크기: {X_train.shape}, 테스트 데이터 크기: {X_test.shape}"))

                            # 데이터 스케일링
                            ml_window.gui_queue.put(('update_status', "데이터 스케일링 시작"))
                            scaler = StandardScaler()
                            X_train = scaler.fit_transform(X_train)
                            X_test = scaler.transform(X_test)
                            ml_window.gui_queue.put(('update_status', "데이터 스케일링 완료"))

                            # 모델 학습
                            ml_window.gui_queue.put(('update_status', "모델 학습 시작"))
                            model = RandomForestClassifier(n_estimators=100, random_state=42)
                            model.fit(X_train, y_train)
                            ml_window.gui_queue.put(('update_status', "모델 학습 완료"))

                            # 모델 평가
                            ml_window.gui_queue.put(('update_status', "모델 평가 시작"))
                            predictions = model.predict(X_test)
                            accuracy = accuracy_score(y_test, predictions)
                            conf_matrix = confusion_matrix(y_test, predictions)
                            ml_window.gui_queue.put(('update_status', f"모델 평가 완료 - 정확도: {accuracy}"))

                            # 모델 저장
                            ml_window.gui_queue.put(('update_status', "모델 저장 시작"))
                            joblib.dump(model, 'random_forest_model.pkl')
                            ml_window.gui_queue.put(('update_status', "모델 저장 완료"))
                            
                            # 성능 지표 업데이트
                            ml_window.gui_queue.put(('update_metrics', accuracy, conf_matrix))
                            ml_window.gui_queue.put(('update_status', "학습 완료!"))
                            
                        except Exception as e:
                            ml_window.gui_queue.put(('update_status', f"모델 학습 중 오류 발생: {str(e)}"))
                    else:
                        print("디버그: 데이터 파일이 아직 생성되지 않음")
                    time.sleep(60)  # 1분마다 데이터 파일 확인
            
            train_thread = threading.Thread(target=monitor_and_train)
            train_thread.daemon = True
            train_thread.start()
            
            # MLTrainingWindow 초기화 시 process_gui_queue 호출
            ml_window.process_gui_queue()
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n프로그램을 종료합니다...")
                packet_core.stop_capture()
        
        # Enter 키를 누를 때까지 대기
        wait_for_enter()
        
    except KeyboardInterrupt:
        print("\n프로그램이 사용자에 의해 중단되었습니다.")
        wait_for_enter()
    except Exception as e:
        print(f"\n오류가 발생했습니다: {str(e)}")
        wait_for_enter()

if __name__ == "__main__":
    main() 