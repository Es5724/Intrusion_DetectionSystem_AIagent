import pandas as pd
import numpy as np
import joblib
import os
import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import seaborn as sns
import queue
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder

class MLTrainingWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("머신러닝 학습 모니터링")
        self.root.geometry("800x600")
        
        # 상태 표시 영역
        self.status_frame = ttk.LabelFrame(self.root, text="학습 상태", padding=10)
        self.status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="대기 중...")
        self.status_label.pack()
        
        # 로그 표시 영역
        self.log_frame = ttk.LabelFrame(self.root, text="학습 로그", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 성능 지표 표시 영역
        self.metrics_frame = ttk.LabelFrame(self.root, text="성능 지표", padding=10)
        self.metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.accuracy_label = ttk.Label(self.metrics_frame, text="정확도: -")
        self.accuracy_label.pack()
        
        # 혼동 행렬 표시 영역
        self.confusion_frame = ttk.LabelFrame(self.root, text="혼동 행렬", padding=10)
        self.confusion_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.figure = Figure(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.confusion_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # GUI 업데이트를 위한 큐 생성
        self.gui_queue = queue.Queue()
        
        # process_gui_queue 호출
        self.process_gui_queue()

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                task = self.gui_queue.get_nowait()
                if task[0] == 'deiconify':
                    self.root.deiconify()
                elif task[0] == 'update_status':
                    self.status_label.config(text=task[1])
                    self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {task[1]}\n")
                    self.log_text.see(tk.END)
                elif task[0] == 'update_metrics':
                    accuracy = task[1]
                    conf_matrix = task[2]
                    self.accuracy_label.config(text=f"정확도: {accuracy:.4f}")
                    
                    # 혼동 행렬 시각화
                    self.figure.clear()
                    ax = self.figure.add_subplot(111)
                    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', ax=ax)
                    ax.set_xlabel('예측 레이블')
                    ax.set_ylabel('실제 레이블')
                    self.canvas.draw()
        except queue.Empty:
            pass
        self.root.after(100, self.process_gui_queue)  # 100ms마다 큐 확인

    def show(self):
        self.root.mainloop()

def train_random_forest(data_path, random_state=42):
    """랜덤포레스트 모델 학습 함수"""
    print(f"데이터 파일 로드: {data_path}")
    preprocessed_df = pd.read_csv(data_path)
    
    # 문자열 데이터를 숫자로 변환
    for column in preprocessed_df.columns:
        if preprocessed_df[column].dtype == 'object':
            # LabelEncoder를 사용하여 문자열을 숫자로 변환
            label_encoder = LabelEncoder()
            preprocessed_df[column] = label_encoder.fit_transform(preprocessed_df[column].astype(str))
            
    # 특성과 레이블 분리
    X = preprocessed_df.drop('protocol_6', axis=1)
    y = preprocessed_df['protocol_6']

    # 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=random_state)

    # 데이터 스케일링
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # 모델 학습
    model = RandomForestClassifier(n_estimators=100, random_state=random_state)
    model.fit(X_train, y_train)

    # 모델 평가
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    print(f'Accuracy: {accuracy}')
    print('Confusion Matrix:')
    print(conf_matrix)

    # 모델 저장
    joblib.dump(model, 'random_forest_model.pkl')
    
    return model, accuracy, conf_matrix

def add_rf_predictions(df):
    """랜덤포레스트 예측 확률을 데이터프레임에 추가"""
    try:
        if os.path.exists('random_forest_model.pkl'):
            rf_model = joblib.load('random_forest_model.pkl')
            feature_cols = [col for col in ['source', 'destination', 'protocol', 'length'] if col in df.columns]
            X_pred = df[feature_cols]
            for col in X_pred.columns:
                if X_pred[col].dtype == 'object':
                    le = LabelEncoder()
                    X_pred[col] = le.fit_transform(X_pred[col].astype(str))
            if hasattr(rf_model, 'predict_proba'):
                rf_prob = rf_model.predict_proba(X_pred)
                if rf_prob.shape[1] > 1:
                    df['rf_prob'] = rf_prob[:, 1]
                else:
                    df['rf_prob'] = rf_prob[:, 0]
            else:
                df['rf_prob'] = np.nan
        else:
            print('random_forest_model.pkl 파일이 없어 예측을 건너뜁니다.')
            df['rf_prob'] = np.nan
    except Exception as e:
        print(f'랜덤포레스트 예측 feature 추가 중 오류: {e}')
        df['rf_prob'] = np.nan
    
    return df 