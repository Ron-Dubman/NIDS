import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self,log_file="ids_alerts.log"):
        #create log file to store alerts of threats
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)
        #handler tells where to write (log_file)
        handler = logging.FileHandler(log_file)
        #formatter keeps the log file formatted in a specified manner
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self,threat,packet_info):
        #create an alert using packet information
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence',0.0),
            'details': threat
        }
        #write threat at warning level
        self.logger.warning(json.dumps(alert))

        #if threat is detected at high confidence level, write it to critical level
        if threat['confidence'] > 0.8:
            self.logger.critical(f"high confidence threat detected: {json.dumps(alert)}")
