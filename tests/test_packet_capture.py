import pytest
import time 
import threading
from scapy.all import IP, TCP, Ether, Raw, ICMP, UDP
from src.packet_capture import PacketCapture

class TestPacketCapture:
    #unit tests for PacketCapture:

    def test_instantiates(self):
        # Test whether PacketCapture object even builds
        pc = PacketCapture()
        assert not pc.stop_capture.is_set()
    
    def test_callback_filters(self):
        # Tests whether callback function correctly filters IPv4/TCP packets
        pc = PacketCapture()
        
        #crafting IPv4/TCP packet from scratch
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP() / Raw(b"test")
        pc.packet_callback(pkt)

        #check if packet enters the queue
        assert pc.packet_queue.qsize() == 1
        retrieved = pc.packet_queue.get_nowait()
        assert IP in retrieved and TCP in retrieved
    
    def test_non_tcp_packets_ignored(self):
        #Tests whether ICMP and UDP packets are correctly filtered out
        pc = PacketCapture()

        #creating ICMP and UDP packets
        icmp_pkt = Ether() / IP() / ICMP()
        udp_pkt = Ether() / IP() / UDP()

        #checking whether crafted packets entered the packet queue
        pc.packet_callback(icmp_pkt)
        pc.packet_callback(udp_pkt)
        assert pc.packet_queue.empty()


    def test_queue_under_load(self):
        #Test whether packets are enqueued correctly under heavy load
        pc = PacketCapture()
        for _ in range(100):
            pkt = Ether() / IP() / TCP()
            pc.packet_callback(pkt)

        assert pc.packet_queue.qsize() == 100