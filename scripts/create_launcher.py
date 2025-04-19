import os
import sys
import subprocess
import tempfile

def create_launcher():
    # 임시 VBS 스크립트 생성
    vbs_script = """
Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "python", "AI_agent.py", "", "runas", 1
"""
    
    # 임시 파일 경로
    temp_dir = tempfile.gettempdir()
    vbs_path = os.path.join(temp_dir, "run_as_admin.vbs")
    
    # VBS 스크립트 작성
    with open(vbs_path, "w") as f:
        f.write(vbs_script)
    
    # 실행 파일 생성
    bat_script = f"""
@echo off
start "" "{vbs_path}"
"""
    
    # 배치 파일 저장
    with open("run_AI_agent.bat", "w") as f:
        f.write(bat_script)
    
    print("실행 파일이 생성되었습니다: run_AI_agent.bat")
    print("이 파일을 실행하면 관리자 권한으로 프로그램이 시작됩니다.")

if __name__ == "__main__":
    create_launcher() 