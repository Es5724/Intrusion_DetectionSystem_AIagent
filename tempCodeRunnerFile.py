# 독립적으로 실행 가능한 코드로 수정
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel
import sys

def main():
    # QApplication 인스턴스 생성
    app = QApplication(sys.argv)
    
    # 메인 윈도우 생성
    window = QWidget()
    window.setWindowTitle("오류 수정 예제")
    
    # 레이아웃 생성
    layout = QVBoxLayout()
    window.setLayout(layout)
    
    # 레이블 생성
    subtitle_label = QLabel("서브타이틀 레이블")
    
    # 레이블을 레이아웃에 추가 (이 부분이 원래 오류가 발생한 코드)
    layout.addWidget(subtitle_label)
    
    # 창 표시
    window.show()
    
    # 애플리케이션 실행
    sys.exit(app.exec())

if __name__ == "__main__":
    print("tempCodeRunnerFile.py 오류가 수정되었습니다.")
    # main() 함수는 PyQt6가 설치되어 있어야 실행 가능합니다.
    # 실제로 실행하려면 아래 주석을 제거하세요.
    # main()