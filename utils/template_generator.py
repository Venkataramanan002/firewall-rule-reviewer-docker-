import io
import json
from typing import Literal, Tuple
import csv
from openpyxl import Workbook


def generate_csv_template() -> bytes:
    headers = [
        'timestamp','src_ip','dst_ip','src_port','dst_port','protocol','action','rule_id','bytes_sent','bytes_received',
        'packets_sent','packets_received','app_name','app_category','url','domain','username','device_name','device_mac',
        'device_os','geo_src_country','geo_src_city','geo_dst_country','geo_dst_city','nat_src_ip','nat_src_port','nat_dst_ip',
        'nat_dst_port','threat_detected','tcp_flags','http_method','user_agent','decryption_status','interface_in','interface_out',
        'zone_from','zone_to','session_end','duration_seconds','file_name','file_type','file_size','file_hash'
    ]
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(headers)
    return out.getvalue().encode('utf-8')


def generate_json_template() -> bytes:
    template = {
        'connections': [
            {
                'timestamp': '2024-01-15T11:03:00Z',
                'src_ip': '192.0.2.10',
                'dst_ip': '203.0.113.20',
                'src_port': 51423,
                'dst_port': 443,
                'protocol': 'tcp',
                'action': 'allow',
                'rule_id': 'R-1001',
                'bytes_sent': 1234,
                'bytes_received': 4321,
                'packets_sent': 10,
                'packets_received': 18,
                'app_name': 'HTTPS',
                'app_category': 'Web Browsing',
                'url': 'https://example.com',
                'domain': 'example.com',
                'username': 'jdoe',
                'device_name': 'fw-cluster-01',
                'device_mac': '00:11:22:33:44:55',
                'device_os': 'PAN-OS',
                'geo_src_country': 'US',
                'geo_src_city': 'New York',
                'geo_dst_country': 'US',
                'geo_dst_city': 'San Francisco',
                'nat_src_ip': '198.51.100.1',
                'nat_src_port': 51423,
                'nat_dst_ip': '203.0.113.20',
                'nat_dst_port': 443,
                'threat_detected': False,
                'tcp_flags': 'SYN',
                'http_method': 'GET',
                'user_agent': 'Mozilla/5.0',
                'decryption_status': 'inspected',
                'interface_in': 'ethernet1/1',
                'interface_out': 'ethernet1/2',
                'zone_from': 'trust',
                'zone_to': 'untrust',
                'session_end': '2024-01-15T11:05:00Z',
                'duration_seconds': 120
            }
        ],
        'threats': [
            {
                'timestamp': '2024-01-15T11:03:00Z',
                'threat_name': 'Malware.Exploit',
                'threat_type': 'malware',
                'severity': 'high',
                'risk_score': 8,
                'src_ip': '192.0.2.10',
                'dst_ip': '203.0.113.20',
                'src_port': 51423,
                'dst_port': 80,
                'file_name': 'data.pcap',
                'file_hash': 'abc123',
                'malware_family': 'Emotet',
                'action_taken': 'blocked',
                'rule_id': 'R-1001',
                'attack_signature': 'BAD_TRAFFIC',
                'cve_id': 'CVE-2023-0001'
            }
        ],
        'firewall_rules': [
            {
                'device_name': 'fw-cluster-01',
                'rule_name': 'AllowWeb',
                'rule_position': 10,
                'source_ip': 'any',
                'source_port': 'any',
                'dest_ip': 'any',
                'dest_port': '80',
                'protocol': 'tcp',
                'action': 'allow',
                'service_name': 'web-service',
                'hit_count': 1000,
                'last_hit': '2024-01-15T11:00:00Z',
                'is_enabled': True
            }
        ],
        'network_topology': [
            {
                'device_name': 'fw-cluster-01',
                'device_type': 'firewall',
                'zone': 'edge',
                'ip_address': '192.0.2.1',
                'ports_open': '80,443',
                'vlan_id': 10,
                'subnet': '192.0.2.0/24',
                'is_entry_point': True
            }
        ],
        'system_health': [
            {
                'timestamp': '2024-01-15T11:00:00Z',
                'device_name': 'fw-cluster-01',
                'cpu_usage_percent': 25.5,
                'memory_usage_percent': 45.6,
                'active_sessions': 100,
                'interface_name': 'ethernet1/1',
                'interface_status': 'up',
                'link_speed_mbps': 1000
            }
        ]
    }

    return json.dumps(template, indent=2).encode('utf-8')


def generate_excel_template() -> bytes:
    wb = Workbook()

    sheets = {
        'Connections': {
            'headers': [
                'timestamp','src_ip','dst_ip','src_port','dst_port','protocol','action','rule_id','bytes_sent','bytes_received',
                'packets_sent','packets_received','app_name','app_category','url','domain','username','device_name','device_mac',
                'device_os','geo_src_country','geo_src_city','geo_dst_country','geo_dst_city','nat_src_ip','nat_src_port','nat_dst_ip',
                'nat_dst_port','threat_detected','tcp_flags','http_method','user_agent','decryption_status','interface_in','interface_out',
                'zone_from','zone_to','session_end','duration_seconds'
            ],
            'example': [
                '2024-01-15T11:03:00Z','192.0.2.10','203.0.113.20',51423,443,'tcp','allow','R-1001',1234,4321,
                10,18,'HTTPS','Web Browsing','https://example.com','example.com','jdoe','fw-cluster-01','00:11:22:33:44:55','PAN-OS',
                'US','New York','US','San Francisco','198.51.100.1',51423,'203.0.113.20',443,False,'SYN','GET','Mozilla/5.0','inspected',
                'ethernet1/1','ethernet1/2','trust','untrust','2024-01-15T11:05:00Z',120
            ]
        },
        'Threats': {
            'headers': ['timestamp','threat_name','threat_type','severity','risk_score','src_ip','dst_ip','src_port','dst_port','file_name','file_hash','malware_family','action_taken','rule_id','attack_signature','cve_id'],
            'example': ['2024-01-15T11:03:00Z','Malware.Exploit','malware','high',8,'192.0.2.10','203.0.113.20',51423,80,'data.pcap','abc123','Emotet','blocked','R-1001','BAD_TRAFFIC','CVE-2023-0001']
        },
        'Firewall_Rules': {
            'headers': ['device_name','rule_name','rule_position','source_ip','source_port','dest_ip','dest_port','protocol','action','service_name','hit_count','last_hit','is_enabled'],
            'example': ['fw-cluster-01','AllowWeb',10,'any','any','any','80','tcp','allow','web-service',1000,'2024-01-15T11:00:00Z',True]
        },
        'Network_Devices': {
            'headers': ['device_name','device_type','zone','ip_address','ports_open','vlan_id','subnet','is_entry_point'],
            'example': ['fw-cluster-01','firewall','edge','192.0.2.1','80,443',10,'192.0.2.0/24',True]
        },
        'System_Health': {
            'headers': ['timestamp','device_name','cpu_usage_percent','memory_usage_percent','active_sessions','interface_name','interface_status','link_speed_mbps'],
            'example': ['2024-01-15T11:00:00Z','fw-cluster-01',25.5,45.6,100,'ethernet1/1','up',1000]
        }
    }

    # Remove default first sheet
    default = wb.active
    wb.remove(default)

    for sheet_name, content in sheets.items():
        ws = wb.create_sheet(sheet_name)
        ws.append(content['headers'])
        ws.append(content['example'])

    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)
    return stream.read()


def generate_template(fmt: Literal['csv', 'json', 'excel']) -> Tuple[bytes, str, str]:
    if fmt == 'csv':
        return (generate_csv_template(), 'text/csv', 'template.csv')
    if fmt == 'json':
        return (generate_json_template(), 'application/json', 'template.json')
    if fmt == 'excel':
        return (generate_excel_template(), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'template.xlsx')
    raise ValueError('Unsupported template format')
