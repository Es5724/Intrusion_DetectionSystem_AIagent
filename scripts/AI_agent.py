import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
# 데이터 전처리 및 스케일링을 위한 모듈
from sklearn.preprocessing import StandardScaler, LabelEncoder
# 데이터 시각화를 위한 모듈
import matplotlib.pyplot as plt
import seaborn as sns
# 기타 필요한 모듈
import numpy as np 

# 외부 CSV 파일에서 데이터 로드
preprocessed_data_path = 'data_set/전처리데이터1.csv'
preprocessed_df = pd.read_csv(preprocessed_data_path)

# IP 주소 인코딩
label_encoder = LabelEncoder()
preprocessed_df['src_ip'] = label_encoder.fit_transform(preprocessed_df['src_ip'])
preprocessed_df['dst_ip'] = label_encoder.fit_transform(preprocessed_df['dst_ip'])

# 특성과 레이블 분리 (예시로 'protocol_6'을 레이블로 사용)
X = preprocessed_df.drop('protocol_6', axis=1)
y = preprocessed_df['protocol_6']

# 데이터 분할
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 모델 학습
model = RandomForestClassifier(n_estimators=100, random_state=42)
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