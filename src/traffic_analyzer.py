from scapy.all import IP, TCP
from collections import defaultdict
class TrafficAnalyzer:
    def __init__(self):
        #stores lists of related packets for each flow
        self.connections = defaultdict(list)
        #stores aggregated statistics of each flow
        #key is (ip_src,ip_dst,port_src,port_dst), value is (packet_count, byte count, start_time, last_time)
        self.flow_stats = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0, 'start_time': None, 'last_time': None})

    def analyze_packet(self,packet):
        #extract flow_key values from relevant packet
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

        #create the flow key
        flow_key = (ip_src,ip_dst,port_src,port_dst)
        #update the flow statistics
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        current_time = packet.time
        if not stats['start_time']:
            stats['start_time'] = current_time
        stats['last_time'] = current_time

        return self.extract_features(packet, stats)

    def extract_features(self,packet,stats):
        #extract derived features from packet flow and current packet
        total_flow_time = stats['last_time'] - stats['start_time']
        if total_flow_time != 0:
            return {
                'packet size': len(packet),
                'flow duration': total_flow_time,
                'packet rate': stats['packet_count'] / total_flow_time,
                'byte rate': stats['byte_count'] / total_flow_time,
                'tcp_flags': packet[TCP].flags,
                'window size': packet[TCP].window
            }
        else:
            return {
                'packet size': len(packet),
                'flow duration': total_flow_time,
                'packet rate': 0,
                'byte rate': 0,
                'tcp_flags': packet[TCP].flags,
                'window size': packet[TCP].window
            }