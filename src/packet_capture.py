from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
    def __init__(self):
        #packet_queue -> packets detected by sniffer enter the queue
        self.packet_queue = queue.Queue()
        #stop_capture -> flipable flag, asks sniffer to exit cleanly
        self.stop_capture = threading.Event()
    
    #callback function, executed everytime scapy detects a packet
    def packet_callback(self, packet):
        #filters out packets, only keeps IPv4/TCP
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
    
    #the function begins capturing packets from the interface
    def start_capture(self, interface = "lo"):
        #separate thread used for sniffing packets
        def capture_thread():
            sniff(iface=interface,prn=self.packet_callback,store=0,stop_filter=lambda _: self.stop_capture.is_set())
        #starts the capture thread
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
    
    #the function flips the stop_capture flag and stops the packet sniffing
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()
