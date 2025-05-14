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

def install_missing_packages():
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} 모듈이 설치되어 있지 않습니다. 설치 중...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"{package} 모듈 설치 완료!")

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