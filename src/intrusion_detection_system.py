from src.packet_capture import PacketCapture
from src.traffic_analyzer import TrafficAnalyzer
from src.detection_engine import DetectionEngine
from src.alert_system import AlertSystem
import queue
from scapy.all import IP, TCP

class IntrusionDetectionSystem:

    def __init__(self,interface="lo"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

    def start(self):
        print(f"IDS starting on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)
                
                    for threat in threats:
                        packet_info = {
                            "source_ip": packet[IP].src,
                            "destination_ip": packet[IP].dst,
                            "source_port": packet[TCP].sport,
                            "destination_port": packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat,packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break


