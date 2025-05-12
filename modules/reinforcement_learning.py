import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
# gym 패키지 임포트 시도 - 없을 경우 자동 설치
try:
    import gym
    from gym import spaces
except ImportError:
    import subprocess
    import sys
    print("gym 모듈이 설치되어 있지 않습니다. 설치 중...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'gym'])
    import gym
    from gym import spaces
    print("gym 모듈 설치 완료!")

from collections import deque
import random
import joblib
import matplotlib.pyplot as plt
import ipaddress
try:
    from scapy.all import IP, TCP, sniff
except ImportError:
    import subprocess
    import sys
    print("scapy 모듈이 설치되어 있지 않습니다. 설치 중...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'scapy'])
    from scapy.all import IP, TCP, sniff
    print("scapy 모듈 설치 완료!")

class NetworkEnv(gym.Env):
    def __init__(self, max_steps=1000):
        super(NetworkEnv, self).__init__()
        
        # 액션 스페이스 정의 (0: 허용, 1: 차단, 2: 모니터링)
        self.action_space = spaces.Discrete(3)
        
        # 관찰 스페이스 정의 (패킷 특성들)
        self.observation_space = spaces.Box(
            low=-np.inf, 
            high=np.inf, 
            shape=(7,),  # 7개의 특성: [src_ip, dst_ip, protocol, length, ttl, flags, rf_prob]
            dtype=np.float32
        )
        
        self.max_steps = max_steps
        self.current_step = 0
        self.total_reward = 0
        self.episode_rewards = []
        self.packet_buffer = []
        self.rf_model = None
        
        # 랜덤포레스트 모델 로드
        try:
            if os.path.exists('random_forest_model.pkl'):
                self.rf_model = joblib.load('random_forest_model.pkl')
        except Exception as e:
            print(f"랜덤포레스트 모델 로드 실패: {e}")
        
    def reset(self):
        self.current_step = 0
        self.total_reward = 0
        self.packet_buffer = []
        # 초기 상태 반환
        return np.zeros(7, dtype=np.float32)
    
    def _extract_packet_features(self, packet):
        """패킷에서 특성 추출"""
        features = np.zeros(7, dtype=np.float32)
        
        if IP in packet:
            # IP 주소를 숫자로 변환
            src_ip = int(ipaddress.IPv4Address(packet[IP].src))
            dst_ip = int(ipaddress.IPv4Address(packet[IP].dst))
            
            features[0] = src_ip / 2**32  # 정규화
            features[1] = dst_ip / 2**32  # 정규화
            features[2] = packet[IP].proto
            features[3] = len(packet) / 1500  # 정규화 (MTU 기준)
            features[4] = packet[IP].ttl / 255  # 정규화
            
            # TCP 플래그 처리
            if TCP in packet:
                flags = packet[TCP].flags
                features[5] = flags / 63  # 정규화 (최대 플래그 값)
            
            # 랜덤포레스트 예측 확률
            if self.rf_model is not None:
                try:
                    packet_df = pd.DataFrame({
                        'source': [packet[IP].src],
                        'destination': [packet[IP].dst],
                        'protocol': [packet[IP].proto],
                        'length': [len(packet)]
                    })
                    prob = self.rf_model.predict_proba(packet_df)[0][1]
                    features[6] = prob
                except:
                    features[6] = 0.5  # 기본값
        
        return features
    
    def step(self, action):
        self.current_step += 1
        
        # 패킷 캡처 및 특성 추출
        try:
            packet = sniff(count=1, timeout=1)[0]
            state = self._extract_packet_features(packet)
        except:
            state = np.zeros(7, dtype=np.float32)
        
        # 보상 계산
        reward = self._calculate_reward(action, packet if 'packet' in locals() else None)
        self.total_reward += reward
        
        # 종료 조건 확인
        done = self.current_step >= self.max_steps
        
        return state, reward, done, {}
    
    def _calculate_reward(self, action, packet):
        """보상 계산 함수"""
        reward = 0
        
        if packet is None:
            return -0.1  # 패킷 캡처 실패 페널티
        
        # 기본 보상
        if action == 0:  # 허용
            if self._is_safe_packet(packet):
                reward += 1.0
            else:
                reward -= 2.0
        elif action == 1:  # 차단
            if not self._is_safe_packet(packet):
                reward += 2.0
            else:
                reward -= 1.0
        else:  # 모니터링
            reward += 0.5
        
        # 탐색 페널티
        if self.current_step < 100:
            reward *= 0.8  # 초기 탐색 단계
        elif self.current_step < 400:
            reward *= 0.9  # 중간 단계
        
        return reward
    
    def _is_safe_packet(self, packet):
        """패킷의 안전성 판단"""
        if self.rf_model is not None:
            try:
                packet_df = pd.DataFrame({
                    'source': [packet[IP].src],
                    'destination': [packet[IP].dst],
                    'protocol': [packet[IP].proto],
                    'length': [len(packet)]
                })
                prediction = self.rf_model.predict(packet_df)[0]
                return prediction == 0  # 0이 정상 패킷
            except:
                return True  # 예측 실패 시 안전하다고 가정
        return True  # 모델이 없으면 안전하다고 가정

class DQNAgent:
    def __init__(self, state_size, action_size):
        self.state_size = state_size
        self.action_size = action_size
        self.memory = deque(maxlen=2000)
        self.gamma = 0.95    # 할인율
        self.epsilon = 1.0   # 탐험률
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
        
    def _build_model(self):
        model = nn.Sequential(
            nn.Linear(self.state_size, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, self.action_size)
        )
        return model
    
    def update_target_model(self):
        self.target_model.load_state_dict(self.model.state_dict())
    
    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))
    
    def act(self, state):
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        state = torch.FloatTensor(state).unsqueeze(0)
        act_values = self.model(state)
        return torch.argmax(act_values[0]).item()
    
    def replay(self, batch_size):
        if len(self.memory) < batch_size:
            return
        
        minibatch = random.sample(self.memory, batch_size)
        for state, action, reward, next_state, done in minibatch:
            target = reward
            if not done:
                next_state = torch.FloatTensor(next_state).unsqueeze(0)
                target = reward + self.gamma * torch.max(self.target_model(next_state)[0]).item()
            
            state = torch.FloatTensor(state).unsqueeze(0)
            target_f = self.model(state)
            target_f[0][action] = target
            
            self.model.zero_grad()
            loss = nn.MSELoss()(self.model(state), target_f)
            loss.backward()
            optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
            optimizer.step()
        
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

def train_rl_agent(env, agent, episodes=500, batch_size=32):
    rewards_history = []
    for episode in range(episodes):
        state = env.reset()
        total_reward = 0
        
        for step in range(env.max_steps):
            action = agent.act(state)
            next_state, reward, done, _ = env.step(action)
            
            agent.remember(state, action, reward, next_state, done)
            state = next_state
            total_reward += reward
            
            if done:
                break
                
            agent.replay(batch_size)
        
        # 에피소드마다 타겟 모델 업데이트
        if episode % 10 == 0:
            agent.update_target_model()
            
        # 에피소드 보상 기록
        rewards_history.append(total_reward)
        
        # 학습 진행 상황 출력
        if episode % 10 == 0:
            avg_reward = np.mean(rewards_history[-10:])
            print(f"에피소드: {episode}, 총 보상: {total_reward:.2f}, 평균 보상: {avg_reward:.2f}, 탐험률: {agent.epsilon:.2f}")
            
    return rewards_history

def plot_training_results(rewards):
    plt.figure(figsize=(12, 6))
    
    # 이동 평균 계산
    window_size = 10
    moving_avg = np.convolve(rewards, np.ones(window_size)/window_size, mode='valid')
    
    # 원본 보상과 이동 평균 플롯
    plt.plot(rewards, alpha=0.3, label='원본 보상')
    plt.plot(moving_avg, label=f'{window_size}회 이동 평균')
    
    plt.title('강화학습 훈련 결과')
    plt.xlabel('에피소드')
    plt.ylabel('총 보상')
    plt.legend()
    plt.grid(True)
    plt.show()

def save_model(agent, filename='dqn_model.pth'):
    """강화학습 모델 저장"""
    torch.save(agent.model.state_dict(), filename)
    print(f"모델이 {filename}에 저장되었습니다.")
    
def load_model(agent, filename='dqn_model.pth'):
    """강화학습 모델 로드"""
    if os.path.exists(filename):
        agent.model.load_state_dict(torch.load(filename))
        agent.target_model.load_state_dict(agent.model.state_dict())
        print(f"모델이 {filename}에서 로드되었습니다.")
        return True
    return False 