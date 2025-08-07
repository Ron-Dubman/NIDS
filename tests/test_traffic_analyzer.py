import pytest
from scapy.all import IP, TCP, Ether, Raw
from src.traffic_analyzer import TrafficAnalyzer

class TestTrafficAnalyzer:
    #unit tests for traffic analyzer

    #tests if constructor works
    def test_instantiates(self):
        ta = TrafficAnalyzer()
        assert isinstance(ta, TrafficAnalyzer)
        assert isinstance(ta.flow_stats,defaultdict)

    def test_first_packet_creates_flow(self):
        #Tests whether the first packet of a flow sets counters correctly
        ta = TrafficAnalyzer()
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=123,dport=80) / Raw(b"abc")
        features = ta.analyze_packet(pkt)

        key = ("1.1.1.1","2.2.2.2",123,80)
        stats = ta.flow_stats[key]

        assert stats["packet_count"] == 1
        assert stats["byte_count"] == len(pkt)
        assert stats["start_time"] == stats["last_time"] == pkt.time
        assert features["packet size"] == len(pkt)

    def test_second_packet_updates_counters(self):
        #Test whether the second packet of a flow updates counters correctly
        ta = TrafficAnalyzer()
        pkt1 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=123,dport=80) / Raw(b"abc")
        pkt2 = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=123,dport=80) / Raw(b"def")

        features1 = ta.analyze_packet(pkt1)
        features2 = ta.analyze_packet(pkt2)

        key = ("1.1.1.1","2.2.2.2",123,80)
        stats = ta.flow_stats[key]
        
        assert stats["packet_count"] == 2
        assert stats["byte_count"] == len(pkt1) + len(pkt2)
        assert stats["start_time"] == pkt1.time
        assert stats["last_time"] == pkt2.time
        assert features2["packet size"] == len(pkt2)

        

