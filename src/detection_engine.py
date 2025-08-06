from sklearn.ensemble import IsolationForest
import numpy as np

def __init__(self):
    #reproducable ML model (random_state=42), that expects 10% of future traffic to be anomalous 
    self.anomaly_detector = IsolationForest(contamination=0.1,random_state=42)
    #stores the signature rules
    self.signature_rules = self.load_signature_rules()
    #buffer that stores "normal" feature vectors, which will help the model understand what a normal vector looks like
    self.training_data = []


def load_signature_rules(self):
    #function that returns a dict keyed by rule name, each rule is a lambda that return True if feature vector triggers it
    return {
        'syn flood':{
            'condition': lambda features: (
                features['tcp_flags'] == 2 and features['packet_rate'] > 100
            )
            },
        'port scan': {
            'condition': lambda features: (
                features['packet_size'] < 100 and features['packet_rate'] > 50
            )
        }

    }

def train_anomaly_detector(self, normal_traffic_date):
    #feed normal feature vectors into the model
    self.anomaly_detector.fit(normal_traffic_date)

def detect_threats(self,features):
    #main detection method, returns list of threats
    threats = []

    #signature-based detection - check for signature threats (rules)
    for rule_name, rule in self.signature_rules.items():
        if rule['condition'](features):
            threats.append({
                'type': 'signature',
                'rule': rule_name,
                'confidence': 1.0
            })

    #anomaly-based detection - check for anomalies

    #build numeric vector for the ML model
    feature_vector = np.array([[
        features['packet_size'],
        features['packet_rate'],
        features['byte_rate']
    ]])
    #calculate anomaly_score and confidence level
    anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
    if anomaly_score < -0.5:
        threats.append({
            'type': 'anomaly',
            'score': anomaly_score,
            'confidence': min(1.0, abs(anomaly_score))
        })
    return threats

