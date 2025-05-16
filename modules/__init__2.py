# 프로젝트 필요 모듈 패키지
###
# 이 파일을 실행하면 필요한 모듈을 자동으로 다운 시켜주는 스크립트입니다.
###

import os
import sys
import subprocess

# 필요한 라이브러리
required_packages = ["gym","torch", "scapy",
                     "pandas", "numpy", "matplotlib",
                     "seaborn", "joblib", "psutil",
                     ""]

# 필요한 패키지 설치
def install_packages():
    print("========== 패키지 설치 시작 ==========")
    success_count = 0 # 패키지 다운 성공 갯수
    fail_count = 0 # 패키지 다운 실패 갯수
    fail_list = [] # 패키지 다운 실패 리스트

    # 패키지 확인 및 설치
    for package in required_packages:
        try: # 패키지 설치 확인
            print(f"{package} 확인 중...")

            # 패키지 설치 확인
            __import__(package)
            print(f"{package} 모듈이 이미 설치되어 있습니다.")

            success_count += 1

        except Exception as e: # 해당 패키지 없음
            print(f"{package} 모듈이 설치되어 있지 않습니다. 설지를 진행 합니다.")

            try: # 패키지 설치
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package],
                                      stderr = subprocess.STDOUT)

                print(f"{package} 모듈 설치 완료!")
                success_count += 1

            except Exception as e: # 패키지 설치 실패
                print(f"{package} 모듈 설치 실패 : {e}")
                fail_count += 1
                fail_list.append(package)

    # 패키지 설치 결과
    print("\n========== 패키지 설치 결과 ==========")
    print(f"성공: {success_count}/{len(required_packages)} 패키지")

    if fail_count > 0: # 패키지 설치 실패한게 있는 경우
        print(f"실패: {fail_count}/{len(required_packages)} 패키지")
        print(f"실패한 패키지: {', '.join(fail_list)}")
        print("\n실패한 패키지를 수동으로 설치하려면 다음 명령어를 실행하세요:")
        for pkg in fail_list:
            print(f"python -m pip install {pkg}")
    else:
        print("\n모든 패키지가 성공적으로 설치되었습니다.")

    return fail_list

# 패키지 설치 실행
failed_packages = install_packages()

# 모듈 임포트 시도
if not failed_packages:
    try:
        # 모듈 임포트 확인
        print("\n모듈 임포트 확인중...")
        from .packet_capture import (PacketCapture,
                                    PacketCaptureCore,
                                    preprocess_packet_data)

        from .reinforcement_learning import (NetworkEnv,
                                            DQNAgent,
                                            train_rl_agent,
                                            plot_training_results,
                                            save_model,
                                            load_model)

        from .ml_models import (MLTrainingWindow,
                               train_random_forest,
                               add_rf_predictions)

        from .utils import (is_colab,
                           is_admin,
                           run_as_admin,
                           clear_screen,
                           wait_for_enter,
                           syn_scan)

        print("모듈 임포트 성공!")

        __all__ = [
            'PacketCapture', 'PacketCaptureCore', 'preprocess_packet_data',
            'NetworkEnv', 'DQNAgent', 'train_rl_agent', 'plot_training_results', 'save_model', 'load_model',
            'MLTrainingWindow', 'train_random_forest', 'add_rf_predictions',
            'is_colab', 'is_admin', 'run_as_admin', 'clear_screen', 'wait_for_enter', 'syn_scan'
        ]

    except Exception as e:
        print(f"\n모듈 임포트 오류 : {e}")
        print("패키지가 설치되었지만 모듈 임포트에 실패했습니다.")

else:
    print("\n일부 패키지가 설치되지 않아 모듈을 임포트할 수 없습니다.")