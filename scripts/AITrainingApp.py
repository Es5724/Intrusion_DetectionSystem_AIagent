from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtGui import QIcon, QCloseEvent
from PyQt6.QtCore import Qt

class AITrainingApp(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_app = parent
        self.setWindowTitle("AI 에이전트 학습")
        layout = QVBoxLayout()
        # 뒤로가기 버튼을 상단 왼쪽에 배치합니다.
        back_button = QPushButton("")
        back_button.setIcon(QIcon.fromTheme("go-previous"))  # 아이콘 설정
        back_button.clicked.connect(self.return_to_main)
        back_button.setFixedSize(30, 30)  # 데이터 전처리 화면의 크기에 맞춤
        layout.addWidget(back_button, alignment=Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.setLayout(layout)

    def closeEvent(self, event: QCloseEvent):
        self.parent_app.show_main_screen()
        event.accept()

    def return_to_main(self):
        self.parent_app.show_main_screen()
        self.close() 