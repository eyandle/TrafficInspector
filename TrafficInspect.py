# By Evan Yandle 3/9/2021
# Licensed to the Public Domain (Free for All)
# Use at your own risk
from scapy.all import sniff
import socket
import chardet
import gzip


class TrafficInspect():
    def __init__(self, server):
        self.server = server
        self.packets = None
        self.ports = []
        self.client_payloads = []
        self.server_payloads = []

        self.__validate_address()

    def listen_for_traffic(self, packet_count=30):
        self.packets = sniff(filter=f'host {self.server}', count=packet_count)
        self.__parse_packet_into_instance()

    def summarize(self):
        print(f'SERVER IP --- {self.server}')
        print(f'Initial Server Payloads:')

        for i in self.server_payloads:
            print(i)

        print('\n\n\n')
        print(f'Initial Client Payloads:')
        for i in self.client_payloads:
            print(i)

    def __validate_address(self):
        self.server = socket.gethostbyname(self.server)

    def __parse_packet_into_instance(self):
        self.__get_unique_ports()
        self.__compile_payloads()

    def __get_unique_ports(self):
        for p in self.packets:
            dport = p.payload.payload.fields.get('dport')
            if (p.payload.dst == self.server) and (dport not in self.ports):
                self.ports.append(dport)

    def __compile_payloads(self):
        for p in self.packets:
            decoded_payload = self.__decode_payload(p.payload.payload.original)
            if p.payload.dst == self.server:
                self.client_payloads.append(decoded_payload)
            else:
                self.server_payloads.append(decoded_payload)

    def __decode_payload(self, _payload):
        encoding = chardet.detect(_payload).get('encoding')
        try:
            return _payload.decode(encoding)
        except:
            return self.__gzip_decode(_payload)

    @staticmethod
    def __gzip_decode(_payload):
        try:
            data = gzip.decompress(_payload)
        except:
            return _payload

        try:
            encoding = chardet.detect(_payload).get('encoding')
            return data.decode(encoding)
        except:
            return _payload


