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

def main():
    try:
        # Colab 환경 확인
        if is_colab():
            print("Google Colab 환경에서는 머신러닝 모델 학습만 가능합니다.")
            print("포트 스캔 기능은 로컬 환경에서만 사용 가능합니다.")
            
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
        
        # 포트 스캔 실행
        target_ip = '127.0.0.1'
        common_ports = [22, 80, 443]  # SSH, HTTP, HTTPS
        
        print("TCP SYN 포트 스캐너 시작")
        print("=" * 50)
        
        scan_results = syn_scan(target_ip, common_ports)
        
        if scan_results is not None:
            print("\n스캔 결과 요약:")
            print(f"열린 포트: {scan_results['open']}")
            print(f"닫힌 포트: {scan_results['closed']}")
            print(f"필터링된 포트: {scan_results['filtered']}")
            print("=" * 50)

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
            print("\n데이터 파일을 찾을 수 없습니다. 포트 스캔만 실행되었습니다.")
        
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