# Intrusion_DetectionSystem 모듈 패키지
import os
import sys
import subprocess

# 필요한 라이브러리 확인 및 설치
required_packages = [    
    'gym', 'torch', 'scapy', 'pandas', 'numpy', 'matplotlib', 'seaborn', 'joblib', 'scikit-learn','PyQt6',     
    'pypcap', 'dpkt', 'netfilterqueue', 'psutil',
    'ipaddress', 'pywin32','pyyaml'
]

# 시스템 패키지로 설치해야 하는 프로그램 목록
system_packages = [
    {
        'name': 'Suricata',
        'windows_install': 'Suricata는 Windows에서 WSL을 통해 설치하거나 공식 웹사이트에서 다운로드해야 합니다.',
        'linux_install': 'sudo add-apt-repository ppa:oisf/suricata-stable && sudo apt-get update && sudo apt-get install suricata',
        'check_command': 'suricata --version'
    }
]

def install_missing_packages():
    # Python 패키지 설치
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} 모듈이 설치되어 있지 않습니다. 설치 중...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"{package} 모듈 설치 완료!")
    
    # 시스템 패키지 확인
    print("\n시스템 패키지 확인:")
    for package in system_packages:
        print(f"- {package['name']}: ", end='')
        try:
            subprocess.run(package['check_command'], shell=True, check=True, capture_output=True)
            print("설치됨")
        except:
            print("설치되지 않음")
            if os.name == 'nt':  # Windows
                print(f"  Windows 설치 방법: {package['windows_install']}")
            else:  # Linux/Mac
                print(f"  Linux 설치 방법: {package['linux_install']}")

# 모듈 임포트 전에 필요한 패키지 설치
install_missing_packages()

# 모듈 임포트
from .packet_capture import PacketCapture, PacketCaptureCore, preprocess_packet_data
from .reinforcement_learning import NetworkEnv, DQNAgent, train_rl_agent, plot_training_results, save_model, load_model
from .ml_models import MLTrainingWindow, train_random_forest, add_rf_predictions
from .utils import is_colab, is_admin, run_as_admin, clear_screen, wait_for_enter, syn_scan

__all__ = [
    'PacketCapture', 'PacketCaptureCore', 'preprocess_packet_data',
    'NetworkEnv', 'DQNAgent', 'train_rl_agent', 'plot_training_results', 'save_model', 'load_model',
    'MLTrainingWindow', 'train_random_forest', 'add_rf_predictions',
    'is_colab', 'is_admin', 'run_as_admin', 'clear_screen', 'wait_for_enter', 'syn_scan'
] 