# 반응형 취약점 차단 AI 에이전트

Main.App.py : 패킷 캡쳐 및 공격성 패킷 생성 기능을 구현한 어플리케이션
AI_agent : 이 프로젝트에서 학습시키고 구현하고자 한 기능을 넣을 어플리케이션 

## 개요
AI 에이전트가 시스템의 네트워크 보안 취약점을 찾아 위험 요소를 학습 및 차단하는 시스템입니다.

AI 에이전트는 다음과 같은 방식으로 데이터를 학습하고 트래픽을 차단합니다:

1. **데이터 수집**:
   - 네트워크 인터페이스에서 실시간으로 패킷을 캡처하여 데이터를 수집합니다. **(사용 라이브러리: Scapy)**
   - 다양한 유형의 트래픽 데이터를 수집하여 학습 데이터셋을 구성합니다.
    - 에이전트 개발 중 자체 제작된 공격성 트래픽 생성 어플리케이션으로 공격성 패킷을 생성 및 전송하여 데이터를 생성합니다.**(사용 라이브러리: Scapy)**
 

2. **데이터 전처리**:
   - 캡처된 패킷 데이터를 전처리하여 머신러닝 모델이 학습할 수 있는 형식으로 변환합니다. **(사용 라이브러리: Pandas)**
   - 패킷의 출발지 IP, 목적지 IP, 프로토콜, 길이, 플래그 등의 정보를 추출합니다.

3. **모델 학습**:
   - 전처리된 데이터를 사용하여 랜덤 포레스트(Random Forest) 알고리즘으로 모델을 학습합니다. **(사용 라이브러리: Scikit-learn)**
   - 랜덤 포레스트는 여러 개의 결정 트리를 사용하여 예측을 수행하는 앙상블 학습 방법입니다.
   - 학습 과정에서 정상 트래픽과 공격성 트래픽을 구분하는 패턴을 학습합니다.

4. **실시간 탐지 및 차단**:
   - 학습된 모델은 실시간으로 네트워크 트래픽을 모니터링하고 분석하여 공격성 패킷을 탐지합니다.
   - 탐지된 공격성 패킷은 즉시 차단되며, 차단된 패킷의 정보는 로그로 기록됩니다.

5. **모델 업데이트**:
   - 새로운 유형의 공격이 발견되거나 네트워크 환경이 변화할 경우, 모델은 주기적으로 업데이트되어야 합니다.
   - 이를 위해 새로운 데이터를 수집하고, 모델을 재학습하여 최신 상태를 유지합니다.

6. **포트 스캔**:
   - 네트워크의 특정 IP 주소에 대해 포트 스캔을 수행하여 열려 있는 포트를 탐지합니다. **(사용 라이브러리: Scapy)**
   - TCP SYN 스캔을 통해 포트의 상태를 확인하고, 열린 포트를 식별합니다.
   - 스캔 결과는 실시간으로 출력되며, 보안 취약점을 식별하는 데 사용됩니다.

이러한 과정을 통해 AI 에이전트는 네트워크 보안을 강화하고, 다양한 공격으로부터 시스템을 보호할 수 있습니다.

## 팀원 정보

- **안상수**: 팀장, 시스템 설계, 메인프로그래밍
- **신명재**: 데이터 학습 및 문서작업
- **민인영**: 데이터 학습 및 이미지 시각화
- **최준형**: 데이터 학습 및 백엔드작업

## 프로그램 작동법

1. **환경 확인**: 프로그램은 Google Colab 환경과 로컬 환경에서 다르게 작동합니다. Colab에서는 머신러닝 모델 학습만 가능하며, 포트 스캔 및 패킷 캡처는 로컬 환경에서만 가능합니다.
2. **관리자 권한 실행**: Windows 환경에서는 관리자 권한으로 실행해야 합니다. 프로그램이 자동으로 관리자 권한으로 재실행됩니다.
3. **패킷 캡처**: 네트워크 인터페이스를 선택하여 패킷 캡처를 시작합니다. Npcap이 설치되어 있어야 하며, 개발 중 와이파이 인터페이스를 자동으로 선택합니다.
4. **실시간 모니터링**: 패킷 캡처 상태와 캡처된 패킷 정보를 실시간으로 모니터링합니다.
5. **데이터 저장 및 전처리**: 캡처된 패킷 데이터를 주기적으로 CSV 파일로 저장하고 전처리합니다.
6. **머신러닝 모델 학습**: 전처리된 데이터를 사용하여 머신러닝 모델을 학습하고 평가합니다. 모델은 RandomForestClassifier를 사용하며, 학습 결과는 웹과 연동되어 시각화됩니다.

## AI 에이전트 기능

### 주요 함수 및 기능

- `is_colab()`: Google Colab 환경인지 확인합니다.
- `is_admin()`: Windows에서 관리자 권한을 확인합니다.
- `run_as_admin()`: 관리자 권한으로 프로그램을 재실행합니다.
- `clear_screen()`: 화면을 지웁니다.
- `wait_for_enter()`: Enter 키를 누를 때까지 대기합니다.
- `print_scan_status(port, status, start_time)`: 스캔 상태를 실시간으로 출력합니다.
- `syn_scan(target_ip, ports)`: TCP SYN 스캔을 수행합니다.

### PacketCapture 클래스

**속성:**
- `interface`: 패킷을 캡처할 네트워크 인터페이스.
- `count`: 캡처할 패킷의 수.

**메서드:**
- `capture_packets()`: 지정된 인터페이스에서 패킷을 캡처합니다.
- `preprocess_packets(packets)`: 캡처된 패킷을 DataFrame으로 전처리합니다.
- `_get_packet_info(packet)`: 패킷의 상세 정보를 추출합니다.
- `_get_tcp_flags(flags)`: TCP 플래그를 추출합니다.
- `save_to_csv(dataframe, filename)`: DataFrame을 CSV 파일로 저장합니다.

### PacketCaptureCore 클래스

**속성:**
- `packet_queue`: 캡처된 패킷을 저장하는 큐.
- `is_running`: 캡처 상태를 나타내는 플래그.
- `packet_count`: 캡처된 패킷의 수.
- `max_packets`: 최대 캡처할 패킷의 수.
- `sniff_thread`: 패킷 캡처를 위한 스레드.
- `capture_completed`: 캡처 완료 상태를 나타내는 플래그.

**메서드:**
- `check_npcap()`: Npcap 설치 여부를 확인합니다.
- `get_network_interfaces()`: 네트워크 인터페이스 목록을 반환합니다.
- `start_capture(interface, max_packets)`: 패킷 캡처를 시작합니다.
- `stop_capture()`: 패킷 캡처를 중지합니다.
- `get_packet_queue()`: 패킷 큐를 반환합니다.
- `get_packet_count()`: 캡처된 패킷 수를 반환합니다.
- `get_packet_dataframe()`: 패킷 큐에 있는 데이터를 DataFrame으로 변환합니다.
- `_process_packet(packet)`: 캡처된 패킷을 처리합니다.

### MLTrainingWindow 클래스

**속성:**
- `root`: Tkinter 루트 윈도우.
- `status_frame`: 학습 상태를 표시하는 프레임.
- `log_frame`: 학습 로그를 표시하는 프레임.
- `metrics_frame`: 성능 지표를 표시하는 프레임.
- `confusion_frame`: 혼동 행렬을 표시하는 프레임.
- `gui_queue`: GUI 업데이트를 위한 큐.

**메서드:**
- `process_gui_queue()`: GUI 큐를 처리하여 상태를 업데이트합니다.
- `show()`: GUI를 표시합니다.
- `update_status()`: 상태를 업데이트합니다.
- `update_metrics()`: 성능 지표를 업데이트합니다.

### 기타 기능

- `main()`: 프로그램의 메인 함수로, Colab 환경 확인, 관리자 권한 확인, 패킷 캡처 시작, 머신러닝 학습 모니터링 등을 수행합니다.

## 에이전트 구조

```
+-----------------------+
|   PacketCapture       |
+-----------------------+
| - interface           |
| - count               |
|-----------------------|
| + capture_packets()   |
| + preprocess_packets()|
| + _get_packet_info()  |
| + _get_tcp_flags()    |
| + save_to_csv()       |
+-----------------------+
         |
         v
+-----------------------+
|   PacketCaptureCore   |
+-----------------------+
| - packet_queue        |
| - is_running          |
| - packet_count        |
| - max_packets         |
| - sniff_thread        |
| - capture_completed   |
|-----------------------|
| + check_npcap()       |
| + get_network_interfaces() |
| + start_capture()     |
| + stop_capture()      |
| + get_packet_queue()  |
| + get_packet_count()  |
| + get_packet_dataframe() |
| + _process_packet()   |
+-----------------------+
         |
         v
+-----------------------+
|   MLTrainingWindow    |
+-----------------------+
| - root                |
| - status_frame        |
| - log_frame           |
| - metrics_frame       |
| - confusion_frame     |
| - gui_queue           |
|-----------------------|
| + process_gui_queue() |
| + show()              |
| + update_status()     |
| + update_metrics()    |
+-----------------------+
```
