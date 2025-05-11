# -*- coding: utf-8 -*-

"""
침입 탐지 시스템 메인 애플리케이션

이 스크립트는 패킷 캡처, 트래픽 생성, 데이터 전처리 등 
다양한 기능을 포함한 침입 탐지 시스템의 주요 GUI 인터페이스를 제공합니다.
"""

import os
import sys
import time
import threading
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
import torch
import ctypes

# 모듈 경로 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# PyQt6 임포트
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QStackedWidget
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt, QSize

# 애플리케이션 모듈 임포트
from packet_collector import PacketCapture, PacketCaptureCore, MainApp as PacketCollectorApp
from TrafficGeneratorApp import TrafficGeneratorApp
from DataPreprocessingApp import DataPreprocessingApp

# 유틸리티 함수
def is_admin():
    """현재 프로세스가 관리자 권한으로 실행 중인지 확인"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """프로그램을 관리자 권한으로 재실행"""
    if is_admin():
        return True
    
    try:
        # VBS 스크립트 생성하여 관리자 권한으로 실행
        script_path = os.path.join(os.environ.get('TEMP', os.getcwd()), 'run_as_admin.vbs')
        with open(script_path, 'w') as f:
            f.write(f'''
Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "{sys.executable}", "{' '.join(sys.argv)}", "", "runas", 1
''')
        
        # VBS 스크립트 실행
        os.system(f'start "" "{script_path}"')
        return True
    except Exception as e:
        print(f"관리자 권한으로 실행 중 오류 발생: {e}")
        return False

def clear_screen():
    """콘솔 화면 지우기"""
    os.system('cls' if os.name == 'nt' else 'clear')

class MainApplication(QMainWindow):
    """메인 애플리케이션 클래스"""
    
    def __init__(self):
        super().__init__()
        
        # 기본 설정
        self.setWindowTitle("침입 탐지 시스템")
        self.setMinimumSize(800, 600)
        
        # 관리자 권한 확인
        if os.name == 'nt' and not is_admin():
            print("관리자 권한이 필요합니다. 관리자 권한으로 재실행합니다...")
            run_as_admin()
            sys.exit(0)
        
        # 중앙 위젯 설정
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # 스택 위젯 생성 (화면 전환용)
        self.stacked_widget = QStackedWidget()
        
        # 메인 화면 레이아웃 설정
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.addWidget(self.stacked_widget)
        
        # 메인 화면 초기화
        self.init_main_screen()
        
        # 패킷 캡처 화면 초기화
        self.packet_collector_app = PacketCollectorApp(self)
        self.stacked_widget.addWidget(self.packet_collector_app)
        
        # 트래픽 생성 화면 초기화
        self.traffic_generator_app = TrafficGeneratorApp(self)
        self.stacked_widget.addWidget(self.traffic_generator_app)
        
        # 데이터 전처리 화면 초기화
        self.data_preprocessing_app = DataPreprocessingApp(self)
        self.stacked_widget.addWidget(self.data_preprocessing_app)
        
        # 시작 화면 표시
        self.show_main_screen()
    
    def init_main_screen(self):
        """메인 시작 화면 초기화"""
        self.main_screen = QWidget()
        layout = QVBoxLayout(self.main_screen)
        
        # 제목 라벨
        title_label = QLabel("침입 탐지 시스템")
        title_font = QFont("Arial", 24, QFont.Weight.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # 버튼 컨테이너
        button_container = QWidget()
        button_layout = QVBoxLayout(button_container)
        button_layout.setSpacing(20)
        
        # 메인 기능 버튼들 추가
        self.add_main_button(button_layout, "패킷 캡처", self.show_packet_collector)
        self.add_main_button(button_layout, "트래픽 생성", self.show_traffic_generator)
        self.add_main_button(button_layout, "데이터 전처리", self.show_data_preprocessing)
        
        # 종료 버튼
        exit_button = QPushButton("종료")
        exit_button.setFixedSize(200, 50)
        exit_button.clicked.connect(self.close)
        button_layout.addWidget(exit_button, alignment=Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(button_container, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # 상태 표시줄
        self.status_label = QLabel("시스템 상태: 준비 완료")
        layout.addWidget(self.status_label, alignment=Qt.AlignmentFlag.AlignBottom)
        
        self.stacked_widget.addWidget(self.main_screen)
    
    def add_main_button(self, layout, text, slot):
        """메인 화면에 버튼 추가"""
        button = QPushButton(text)
        button.setFixedSize(200, 50)
        button.clicked.connect(slot)
        layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)
    
    def show_main_screen(self):
        """메인 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.main_screen)
    
    def show_packet_collector(self):
        """패킷 캡처 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.packet_collector_app)
    
    def show_traffic_generator(self):
        """트래픽 생성 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.traffic_generator_app)
    
    def show_data_preprocessing(self):
        """데이터 전처리 화면 표시"""
        self.stacked_widget.setCurrentWidget(self.data_preprocessing_app)

def main():
    """메인 함수"""
    app = QApplication(sys.argv)
    window = MainApplication()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()