# 필요한 모듈과 클래스들 임포트
import sys
import ctypes
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QStackedWidget, QHBoxLayout, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox, QFileDialog
from PyQt6.QtGui import QIcon
from packet_collector import PacketCapture, PacketCaptureCore
import pandas as pd
from sklearn.preprocessing import StandardScaler
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from DataPreprocessingApp import DataPreprocessingApp
from AITrainingApp import AITrainingApp
from TrafficGeneratorApp import TrafficGeneratorApp
import packet_collector

# 관리자 권한으로 스크립트를 재실행
def run_as_admin():
    """관리자 권한으로 스크립트를 재실행합니다."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    else:
        # 관리자 권한으로 재실행
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

class PacketCaptureThread(QThread):
    packets_captured = pyqtSignal(object)

    def __init__(self, interface, count):
        super().__init__()
        self.interface = interface
        self.count = count

    def run(self):
        packet_capture = PacketCapture(interface=self.interface, count=self.count)
        packets = packet_capture.capture_packets()
        self.packets_captured.emit(packets)

class FileLoadThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, core, file_path):
        super().__init__()
        self.core = core
        self.file_path = file_path

    def run(self):
        try:
            self.core.load_pcapng_file(self.file_path)
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

# 메인 애플리케이션 클래스
class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("취약점 자동진단 시스템")
        self.setWindowIcon(QIcon("icon.png"))
        self.core = PacketCaptureCore()
        self.check_for_updates()
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # 메인 화면 설정
        self.main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 메인 화면 버튼 설정
        button_width = int(300 * 1.5)  # 기존 버튼 크기의 1.5배를 정수로 변환

        main_button_capture = QPushButton("패킷 캡처")
        main_button_capture.setFixedSize(button_width, 30)
        main_button_capture.clicked.connect(self.show_packet_capture)
        main_layout.addWidget(main_button_capture, alignment=Qt.AlignmentFlag.AlignCenter)

        main_button_traffic_gen = QPushButton("트래픽 생성")
        main_button_traffic_gen.setFixedSize(button_width, 30)
        main_button_traffic_gen.clicked.connect(self.show_traffic_generator)
        main_layout.addWidget(main_button_traffic_gen, alignment=Qt.AlignmentFlag.AlignCenter)

        main_button_data_preprocessing = QPushButton("데이터 전처리")
        main_button_data_preprocessing.setFixedSize(button_width, 30)
        main_button_data_preprocessing.clicked.connect(self.show_data_preprocessing)
        main_layout.addWidget(main_button_data_preprocessing, alignment=Qt.AlignmentFlag.AlignCenter)

        main_button_ai_training = QPushButton("AI 에이전트 학습")
        main_button_ai_training.setFixedSize(button_width, 30)
        main_button_ai_training.clicked.connect(self.show_ai_training)
        main_layout.addWidget(main_button_ai_training, alignment=Qt.AlignmentFlag.AlignCenter)

        self.main_widget.setLayout(main_layout)
        self.stacked_widget.addWidget(self.main_widget)

        # 패킷 캡처 화면 설정
        self.packet_widget = QWidget()
        packet_layout = QVBoxLayout()

        # 제어 버튼 레이아웃 설정
        control_layout = QHBoxLayout()
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))
        back_button.clicked.connect(self.show_main_screen)
        back_button.setFixedSize(30, 30)
        control_layout.addWidget(back_button)

        interface_label = QLabel("네트워크 인터페이스:")
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.core.get_network_interfaces())
        packet_count_label = QLabel("최대 패킷 수:")
        self.packet_count_combo = QComboBox()
        self.packet_count_combo.addItems(["100", "500", "1000", "300000"])
        start_button = QPushButton("캡처 시작")
        stop_button = QPushButton("캡처 중지")
        load_button = QPushButton("파일 불러오기")
        self.save_button = QPushButton("데이터 저장")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_captured_data)
        control_layout.addWidget(interface_label)
        control_layout.addWidget(self.interface_combo)
        control_layout.addWidget(packet_count_label)
        control_layout.addWidget(self.packet_count_combo)
        control_layout.addWidget(start_button)
        control_layout.addWidget(stop_button)
        control_layout.addWidget(load_button)
        control_layout.addWidget(self.save_button)

        self.status_label = QLabel("상태: 대기 중")

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)

        packet_layout.addLayout(control_layout)
        packet_layout.addWidget(self.status_label)
        packet_layout.addWidget(self.packet_table)
        self.packet_widget.setLayout(packet_layout)

        self.stacked_widget.addWidget(self.packet_widget)

        self.setup_timer()
        start_button.clicked.connect(self.start_capture)
        stop_button.clicked.connect(self.stop_capture)
        load_button.clicked.connect(self.load_pcapng_file)

    def show_main_screen(self):
        self.stacked_widget.setCurrentWidget(self.main_widget)

    # 패킷 캡처 화면으로 전환.
    def show_packet_capture(self):
        print("패킷 캡처 화면으로 전환 시도")
        if self.packet_widget in self.stacked_widget.children():
            print("패킷 위젯이 스택에 포함되어 있습니다.")
        else:
            print("패킷 위젯이 스택에 포함되어 있지 않습니다.")
        self.stacked_widget.setCurrentWidget(self.packet_widget)

        # 시스템에서 사용 가능한 네트워크 인터페이스 중 하나를 선택
        interfaces = self.core.get_network_interfaces()
        print(f"사용 가능한 네트워크 인터페이스: {interfaces}")
        if not interfaces:
            QMessageBox.critical(self, "인터페이스 오류", "사용 가능한 네트워크 인터페이스가 없습니다.")
            return
        selected_interface = interfaces[0]  # 첫 번째 인터페이스를 선택
        print(f"선택된 인터페이스: {selected_interface}")

        # PacketCaptureThread를 사용하여 패킷 캡처를 별도의 스레드에서 실행
        self.capture_thread = PacketCaptureThread(interface=selected_interface, count=100)
        self.capture_thread.packets_captured.connect(self.handle_packets_captured)
        self.capture_thread.start()

    def handle_packets_captured(self, packets):
        packet_capture = PacketCapture(interface='eth0')  # 예시 인터페이스 이름 사용
        dataframe = packet_capture.preprocess_packets(packets)
        print(dataframe.head())  # 데이터프레임의 첫 몇 줄을 출력하여 확인

    # 데이터 전처리 화면으로 전환.
    def show_data_preprocessing(self):
        if not hasattr(self, 'preprocess_widget') or self.preprocess_widget is None:
            self.preprocess_widget = DataPreprocessingApp(self)
            self.stacked_widget.addWidget(self.preprocess_widget)
        self.stacked_widget.setCurrentWidget(self.preprocess_widget)

    # 업데이트를 확인.
    def check_for_updates(self):
        # 업데이트 확인 및 설치 로직을 여기에 추가.
        print("업데이트 확인 중...")
        # 현재는 단순히 업데이트 확인 중임을 출력.

    # AI 에이전트 학습 화면으로 전환합니다.
    def show_ai_training(self):
        if not hasattr(self, 'ai_training_widget') or self.ai_training_widget is None:
            self.ai_training_widget = AITrainingApp(self)
            self.stacked_widget.addWidget(self.ai_training_widget)
        self.stacked_widget.setCurrentWidget(self.ai_training_widget)

    # 학습 분석 및 결과 화면으로 전환.
    def show_analysis_results(self):
        # 학습 분석 및 결과 화면으로 전환
        print("학습 분석 및 결과 화면으로 전환")

    # 자동 진단 시스템을 활성화.
    def activate_auto_diagnosis(self):
        # 자동 진단 시스템 활성화
        print("자동 진단 시스템 활성화")

    # 트래픽 생성 화면으로 전환.
    def show_traffic_generator(self):
        if not hasattr(self, 'traffic_gen_widget') or self.traffic_gen_widget is None:
            self.traffic_gen_widget = TrafficGeneratorApp(self)
            self.stacked_widget.addWidget(self.traffic_gen_widget)
        self.stacked_widget.setCurrentWidget(self.traffic_gen_widget)

    def setup_timer(self):
        """타이머를 설정합니다."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_packet_table)
        self.update_timer.start(200)

    def update_packet_table(self):
        """패킷 테이블을 업데이트합니다."""
        packet_queue = self.core.get_packet_queue()
        new_packets = []
        while not packet_queue.empty():
            packet = packet_queue.get()
            new_packets.append(packet)
        if not new_packets:
            return
        current_row = self.packet_table.rowCount()
        self.packet_table.setRowCount(current_row + len(new_packets))
        for i, packet in enumerate(new_packets):
            self.packet_table.setItem(current_row + i, 0, QTableWidgetItem(str(packet.get('no', ''))))
            self.packet_table.setItem(current_row + i, 1, QTableWidgetItem(str(packet.get('source', ''))))
            self.packet_table.setItem(current_row + i, 2, QTableWidgetItem(str(packet.get('destination', ''))))
            self.packet_table.setItem(current_row + i, 3, QTableWidgetItem(str(packet.get('protocol', ''))))
            self.packet_table.setItem(current_row + i, 4, QTableWidgetItem(str(packet.get('length', ''))))
            info_item = QTableWidgetItem(str(packet.get('info', '')))
            info_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.packet_table.setItem(current_row + i, 5, info_item)
        self.packet_table.scrollToBottom()

    def start_capture(self):
        """패킷 캡처를 시작합니다."""
        selected_interface = self.interface_combo.currentText()
        max_packets = int(self.packet_count_combo.currentText())
        if self.core.start_capture(selected_interface, max_packets):
            self.status_label.setText(f"상태: 캡처 중 (0/{max_packets})")
            QMessageBox.information(self, "캡처 시작", "패킷 캡처가 시작되었습니다.")
            self.save_button.setEnabled(False)  # Disable save button during capture
        else:
            QMessageBox.warning(self, "캡처 실패", "패킷 캡처를 시작할 수 없습니다.")

    def stop_capture(self):
        """패킷 캡처를 중지합니다."""
        packet_count = self.core.stop_capture()
        self.status_label.setText("상태: 중지됨")
        QMessageBox.information(self, "캡처 완료", f"캡처된 패킷 수: {packet_count}")
        self.save_button.setEnabled(True)  # Enable save button after capture

    def load_pcapng_file(self):
        """PCAPNG 파일을 불러옵니다."""
        file_path, _ = QFileDialog.getOpenFileName(self, "pcapng 파일 선택", "", "PCAPNG Files (*.pcapng);;All Files (*)")
        if file_path:
            self.file_load_thread = FileLoadThread(self.core, file_path)
            self.file_load_thread.progress.connect(self.update_progress)
            self.file_load_thread.finished.connect(self.file_load_finished)
            self.file_load_thread.error.connect(self.file_load_error)
            self.file_load_thread.start()

    def save_captured_data(self):
        """캡처된 패킷 데이터를 저장합니다."""
        file_path, _ = QFileDialog.getSaveFileName(self, "파일 저장", "", "CSV Files (*.csv);;All Files (*)")
        if file_path:
            dataframe = self.core.get_packet_dataframe()
            dataframe.to_csv(file_path, index=False)
            QMessageBox.information(self, "저장 완료", "데이터가 성공적으로 저장되었습니다.")

# 메인 함수.
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    app.exec()