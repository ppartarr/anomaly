#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.extractors.audit.arp import ARPFeatureExtractor
from anomaly.extractors.audit.credentials import CredentialsFeatureExtractor
from anomaly.extractors.audit.device_profile import DeviceProfileFeatureExtractor
from anomaly.extractors.audit.dhcpv4 import DHCPv4ProfileFeatureExtractor
from anomaly.extractors.audit.dhcpv6 import DHCPv6ProfileFeatureExtractor
from anomaly.extractors.audit.dns import DNSFeatureExtractor
from anomaly.extractors.audit.ethernet import EthernetFeatureExtractor
from anomaly.extractors.audit.exploit import ExploitFeatureExtractor
from anomaly.extractors.audit.http import HTTPFeatureExtractor
from anomaly.extractors.audit.icmpv4 import ICMPv4FeatureExtractor
from anomaly.extractors.audit.icmpv6 import ICMPv6FeatureExtractor
from anomaly.extractors.audit.igmp import IGMPFeatureExtractor
from anomaly.extractors.audit.ip_profile import IPProfileFeatureExtractor
from anomaly.extractors.audit.ipv4 import IPv4FeatureExtractor
from anomaly.extractors.audit.ipv6_hop_by_hop import IPv6HopByHopFeatureExtractor
from anomaly.extractors.audit.ipv6 import IPv6FeatureExtractor
from anomaly.extractors.audit.ntp import NTPFeatureExtractor
from anomaly.extractors.audit.service import ServiceFeatureExtractor
from anomaly.extractors.audit.sip import SIPFeatureExtractor
from anomaly.extractors.audit.software import SoftwareFeatureExtractor
from anomaly.extractors.audit.tcp import TCPFeatureExtractor
from anomaly.extractors.audit.tls_client_hello import TLSClientHelloFeatureExtractor
from anomaly.extractors.audit.tls_server_hello import TLSServerHelloFeatureExtractor
from anomaly.extractors.audit.udp import UDPFeatureExtractor
from anomaly.extractors.audit.vulnerability import VulnerabilityFeatureExtractor


audit_records = {
    'ARP': {
        'socket': '/tmp/ARP.sock',
        'feature_extractor': ARPFeatureExtractor
    },
    'Connection': {
        'socket': '/tmp/Connection.sock',
        'feature_extractor': ConnectionFeatureExtractor
    },
    'Credentials': {
        'socket': '/tmp/Credentials.sock',
        'feature_extractor': CredentialsFeatureExtractor
    },
    'DeviceProfile': {
        'socket': '/tmp/DeviceProfile.sock',
        'feature_extractor': DeviceProfileFeatureExtractor
    },
    'DHCPv4': {
        'socket': '/tmp/DHCPv4.sock',
        'feature_extractor': DHCPv4ProfileFeatureExtractor
    },
    'DHCPv6': {
        'socket': '/tmp/DHCPv6.sock',
        'feature_extractor': DHCPv6ProfileFeatureExtractor
    },
    'DNS': {
        'socket': '/tmp/DNS.sock',
        'feature_extractor': DNSFeatureExtractor
    },
    'Ethernet': {
        'socket': '/tmp/Ethernet.sock',
        'feature_extractor': EthernetFeatureExtractor
    },
    'Exploit': {
        'socket': '/tmp/Exploit.sock',
        'feature_extractor': ExploitFeatureExtractor
    },
    'HTTP': {
        'socket': '/tmp/HTTP.sock',
        'feature_extractor': HTTPFeatureExtractor
    },
    'ICMPv4': {
        'socket': '/tmp/ICMPv4.sock',
        'feature_extractor': ICMPv4FeatureExtractor
    },
    'ICMPv6': {
        'socket': '/tmp/ICMPv6.sock',
        'feature_extractor': ICMPv6FeatureExtractor
    },
    'IGMP': {
        'socket': '/tmp/IGMP.sock',
        'feature_extractor': IGMPFeatureExtractor
    },
    'IPProfile': {
        'socket': '/tmp/IPProfile.sock',
        'feature_extractor': IPProfileFeatureExtractor
    },
    'IPv4': {
        'socket': '/tmp/IPv4.sock',
        'feature_extractor': IPv4FeatureExtractor
    },
    'IPv6HopByHop': {
        'socket': '/tmp/IPv6HopByHop.sock',
        'feature_extractor': IPv6HopByHopFeatureExtractor
    },
    'IPv6': {
        'socket': '/tmp/IPv6.sock',
        'feature_extractor': IPv6FeatureExtractor
    },
    'NTP': {
        'socket': '/tmp/NTP.sock',
        'feature_extractor': NTPFeatureExtractor
    },
    'Service': {
        'socket': '/tmp/Service.sock',
        'feature_extractor': ServiceFeatureExtractor
    },
    'SIP': {
        'socket': '/tmp/SIP.sock',
        'feature_extractor': SIPFeatureExtractor
    },
    'Software': {
        'socket': '/tmp/Software.sock',
        'feature_extractor': SoftwareFeatureExtractor
    },
    'TCP': {
        'socket': '/tmp/TCP.sock',
        'feature_extractor': TCPFeatureExtractor
    },
    'TLSClientHello': {
        'socket': '/tmp/TLSClientHello.sock',
        'feature_extractor': TLSClientHelloFeatureExtractor
    },
    'TLSServerHello': {
        'socket': '/tmp/TLSServerHello.sock',
        'feature_extractor': TLSServerHelloFeatureExtractor
    },
    'UDP': {
        'socket': '/tmp/UDP.sock',
        'feature_extractor': UDPFeatureExtractor
    },
    'Vulnerability': {
        'socket': '/tmp/Vulnerability.sock',
        'feature_extractor': VulnerabilityFeatureExtractor
    }
}
