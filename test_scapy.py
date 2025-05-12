#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scapy 기본 테스트 스크립트
로컬호스트로 패킷을 전송하여 Scapy가 제대로 설치되었는지 확인합니다.
"""

import sys
import time
from scapy.all import conf, IP, TCP, UDP, ICMP, send, sr1

def main():
    """메인 테스트 함수"""
    print("Scapy 테스트 시작...")
    print(f"Scapy 버전: {conf.version}")
    print(f"기본 인터페이스: {conf.iface}")
    
    # 테스트할 IP 주소 (로컬호스트)
    target_ip = "127.0.0.1"
    
    try:
        # UDP 패킷 전송 테스트
        print("\n[UDP 테스트]")
        udp_packet = IP(dst=target_ip)/UDP(dport=12345)/b"UDP_TEST"
        send(udp_packet, verbose=1)
        print("UDP 패킷 전송 성공!")
        
        # TCP 패킷 전송 테스트
        print("\n[TCP 테스트]")
        tcp_packet = IP(dst=target_ip)/TCP(dport=80, flags="S")/b"TCP_TEST"
        send(tcp_packet, verbose=1)
        print("TCP 패킷 전송 성공!")
        
        # ICMP 패킷 전송 테스트 (ping)
        print("\n[ICMP 테스트]")
        icmp_packet = IP(dst=target_ip)/ICMP()
        response = sr1(icmp_packet, timeout=1, verbose=1)
        if response:
            print(f"응답 수신: {response.summary()}")
        else:
            print("응답 없음")
        
        print("\n모든 테스트 완료!")
        return 0
        
    except Exception as e:
        print(f"오류 발생: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 