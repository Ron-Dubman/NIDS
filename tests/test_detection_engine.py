import pytest
import numpy as np
from src.detection_engine import DetectionEngine

class TestDetectionEngine():
    #unit tests for detection engine

    def test_instantiates(self):
        #Test if constructor works
        de = DetectionEngine()
        assert de.signature_rules
        assert de.training_data == []

    def test_syn_flood_threat(self,monkeypatch):
        #Test whether a syn flood threat is detected properly
        de = DetectionEngine()
        #patch score_sample to always return normal score (0)
        def mock_score(x):
            return [0]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"tcp_flags": 2, "packet_rate": 200, "byte_rate": 1000, "packet_size": 60}
        threats = de.detect_threats(features)
        rule_names = [t["rule"] for t in threats if t["type"] == "signature"]
        assert "syn flood" in rule_names

    def test_not_syn_flood_threat(self,monkeypatch):
        #Test whether the syn flood rule doesnt trigger when there isnt a syn flood threat detected
        de = DetectionEngine()
        #patch score_sample to always return normal score (0)
        def mock_score(x):
            return [0]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"tcp_flags": 16, "packet_rate": 10, "byte_rate": 1000, "packet_size":60}
        threats = de.detect_threats(features)
        rule_names = [t["rule"] for t in threats if t["type"] == "signature"]
        assert "syn flood" not in rule_names
    
    def test_port_scan_threat(self, monkeypatch):
        #Test whether a port scan threat is detected properly
        de = DetectionEngine()
        #patch score_sample to always return normal score (0)
        def mock_score(x):
            return [0]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"packet_size": 60, "packet_rate": 60, "byte_rate": 300, "tcp_flags": 16}
        threats = de.detect_threats(features)
        rule_names = [t["rule"] for t in threats if t["type"] == "signature"]
        assert "port scan" in rule_names

    def test_not_port_scan_threat(self, monkeypatch):
        #Test whether the port scan rule doesnt trigger when there isnt a port scan threat detected
        de = DetectionEngine()
        #patch score_sample to always return normal score (0)
        def mock_score(x):
            return [0]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"packet_size": 120, "packet_rate": 10, "byte_rate": 300, "tcp_flags": 16}
        threats = de.detect_threats(features)
        rule_names = [t["rule"] for t in threats if t["type"] == "signature"]
        assert "port scan" not in rule_names
    
    def test_anomaly_threat(self,monkeypatch):
        #Test whether anomaly is detected properly
        de = DetectionEngine()
        #patch score_sample to always return anomalous score (-0.9)
        def mock_score(x):
            return [-0.9]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"packet_size": 9999, "packet_rate": 9999, "byte_rate": 9999, "tcp_flags":16}
        threats = de.detect_threats(features)
        assert any(t['type'] == 'anomaly' for t in threats)
    
    def test_not_anomaly_threat(self,monkeypatch):
        #Test whether anomaly rule doesnt trigger when there isnt an anomaly detected
        de = DetectionEngine()
        #patch score_sample to always return normal score (0)
        def mock_score(x):
            return [0]
        monkeypatch.setattr(de.anomaly_detector, "score_samples", mock_score)

        features = {"packet_size": 9999, "packet_rate": 9999, "byte_rate": 9999, "tcp_flags":16}
        threats = de.detect_threats(features)
        assert not any(t['type'] == 'anomaly' for t in threats)
    
    def test_training_succesful(self):
        #Test whether ML model succesfully computes input
        de = DetectionEngine()
        normal = np.array([[100,10,1000],[200,20,2000]])
        de.train_anomaly_detector(normal)
        assert de.anomaly_detector.n_features_in_ == 3
