import argparse
import numpy as np
from src.intrusion_detection_system import IntrusionDetectionSystem

normal_features = np.array([[64,8.33,533], [150,4.0,600], [52,22.2,1155]])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS")
    parser.add_argument("--train", action="store_true", help= "train Isolation Forest ML model before start")
    args = parser.parse_args()

    ids = IntrusionDetectionSystem()
    if args.train:
        ids.detection_engine.train_anomaly_detector(normal_features)
        print("✅ Anomaly model trained on normal vectors!")
    ids.start()