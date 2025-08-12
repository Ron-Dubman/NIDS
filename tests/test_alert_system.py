import json
import tempfile
import os
import pytest
from src.alert_system import AlertSystem

class TestAlertSystem:
    #unit tests for alert system

    @pytest.fixture
    def temp_log(Self):
        #create temp log file and yield path
        fd, path = tempfile.mkstemp(suffix=".log")
        yield path
        os.close(fd)
        os.remove(path)
    
    def test_instantiates(self,temp_log):
        #tests if constructor works
        alert = AlertSystem(temp_log)
        assert alert.logger.name == "IDS_Alerts"
    
    def test_warning_alert(slef,temp_log):
        #tests if warning level alerts are written properly to the log file
        alert = AlertSystem(temp_log)
        #create threat & packet for alert (should be written in warning because confidence level <= 0.8)
        threat = {"type": "anomaly","score": -0.6,"confidence": 0.6}
        packet = {"source_ip": "1.1.1.1","destination_ip": "2.2.2.2"}

        alert.generate_alert(threat,packet)
        
        with open(temp_log) as f:
            lines = f.readlines()
        assert len(lines) == 1
        record = json.loads(lines[0].split(" - ", 2)[-1]) #remove time stamp
        assert record["threat_type"] == "anomaly"
        assert record["source_ip"] == "1.1.1.1"
        assert record["destination_ip"] == "2.2.2.2"

    def test_critical_level(self,temp_log):
        #tests if critical level alerts are written properly to the log file
        alert = AlertSystem(temp_log)
        #create threat & packet for alert (should be written in critical because confidence level > 0.8)
        threat = {"type": "anomaly","score": -0.9,"confidence": 0.9}
        packet = {"source_ip": "1.1.1.1","destination_ip": "2.2.2.2"}

        alert.generate_alert(threat,packet)

        with open(temp_log) as f:
            lines = f.readlines()
        
        warnings = [l for l in lines if "WARNING" in l]
        criticals = [l for l in lines if "CRITICAL" in l]

        assert len(warnings) == 1
        assert len(criticals) == 1

