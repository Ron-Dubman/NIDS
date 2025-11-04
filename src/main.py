import argparse
import time
import queue
import os
import numpy as np
from src.intrusion_detection_system import IntrusionDetectionSystem


def learn_normal_traffic(learn_duration=60):
    print(f"🔬 Starting learning mode for {learn_duration} seconds...")
    print("Please let the system run normally. Do NOT launch any attacks.")
    ids = IntrusionDetectionSystem()
    ids.packet_capture.start_capture(ids.interface)
    
    normal_vectors = []
    start_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            if current_time - start_time > learn_duration:
                break
                
            try:
                packet = ids.packet_capture.packet_queue.get(timeout=1)
                features = ids.traffic_analyzer.analyze_packet(packet)
                
                if features:
                    # Store the 3 key features for the ML model
                    normal_vectors.append([
                        features['packet_size'],
                        features['packet_rate'],
                        features['byte_rate']
                    ])
                    
            except queue.Empty:
                continue
    
    except KeyboardInterrupt:
        print("\nLearning interrupted by user.")
        
    finally:
        ids.packet_capture.stop()

    if normal_vectors:
        # Save the captured data to a file
        training_data = np.array(normal_vectors)
        np.save('normal_traffic.npy', training_data)
        print(f"\n✅ Learning complete. Saved {len(training_data)} normal vectors to 'normal_traffic.npy'.")
    else:
        print("\n⚠️ No traffic was captured. Could not create training file.")

    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS")
    parser.add_argument("--learn", type=int, help="Run in learning mode for N seconds to capture normal traffic", metavar="SECONDS")
    parser.add_argument("--train", action="store_true", help="Train Isolation Forest ML model before start")
    args = parser.parse_args()

    ids = IntrusionDetectionSystem()
    if args.learn:
        learn_duration = args.learn
        print(f"Learning mode is set for {learn_duration} seconds...")
        learn_normal_traffic(learn_duration)
    elif args.train:
        if not os.path.exists('normal_traffic.npy'):
            print("❌ Error: 'normal_traffic.npy' not found.")
            print("Please run the NIDS with the --learn flag first:")
            print(f"   sudo {os.sys.argv[0]} --learn")
        else:
            print("💾 Loading 'normal_traffic.npy' for training...")
            normal_features = np.load('normal_traffic.npy')
            if len(normal_features) < 100:
                print("⚠️ Warning: less than 100 samples loaded, Model may be inaccurate.")
            ids.detection_engine.train_anomaly_detector(normal_features)
            print("✅ Anomaly model trained on normal vectors!")
            ids.start()

    