import socket
import random
import struct
import threading
import requests
import ftplib
import sys
from colorama import Fore, Back, Style

MAX_NUMBER_OF_THREADS = 1  # maximum numbers of threads is usually 300


def gen_ip():
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))


def debug_msg(msg):
    print(Fore.GREEN + f"[ DEBUG ]: {msg}" + Fore.RESET)


def debug_error(msg):
    print(Fore.RED + f"[ DEBUG ]: {msg}" + Fore.RESET)


def debug_warning(msg):
    print(Fore.YELLOW + f"[ DEBUG ]: {msg}" + Fore.RESET)


def scan_for_https(ip: str) -> [bool, str]:
    try:
        response = requests.get('http://' + ip, timeout=5)
        if response.status_code == 200 and response.headers["title"] == "Apache2 Ubuntu Default Page":
            return True, "http"
        response = requests.get('https://' + ip, timeout=5)
        if response.status_code == 200 and response.headers["title"] == "Apache2 Ubuntu Default Page":
            return True, "https"
        return False, ""
    except requests.exceptions.Timeout:
        return False, ""
    except requests.exceptions.ConnectionError:
        return False, ""
    except Exception as e:
        return False, ""


def scan_for_ftp(ip: str) -> [bool, str]:
    try:
        with ftplib.FTP(ip, timeout=5) as session:
            try:
                session.login("anonymous", "")
                try:
                    ftp_dir = session.nlst()
                    for obj in ftp_dir:
                        if obj != ".." or obj != ".":
                            return True, "ftp"
                    return False, "ftp"
                except ftplib.all_errors as e:
                    return False, "ftp"
            except ftplib.error_perm as e:
                return False, "ftp"
    except ftplib.error_proto as e:
        return False, "ftp"
    except socket.timeout:
        return False, "ftp"
    except Exception as e:
        return False, "ftp"


def thread_process():
    while True:
        ip_information = {
            "ip": "",
            "allowed_protocols": []
        }
        ip_to_scan = gen_ip()
        ip_information["ip"] = ip_to_scan

        https_request = scan_for_https(ip_to_scan)
        if https_request[0]:
            if https_request[1] == "https":
                ip_information["allowed_protocols"].append((https_request[1], "443"))
            if https_request[1] == "http":
                ip_information["allowed_protocols"].append((https_request[1], "80"))

        ftp_request = scan_for_ftp(ip_to_scan)
        if ftp_request[0]:
            ip_information["allowed_protocols"].append((ftp_request[1], "21"))

        if len(ip_information["allowed_protocols"]) != 0:
            debug_msg(f"{ip_to_scan}\n")
            for prot in ip_information["allowed_protocols"]:
                debug_msg(f"Protocol: {prot[0]} ({prot[1]})")




if __name__ == '__main__':
    try:
        for i in range(MAX_NUMBER_OF_THREADS):
            t = threading.Thread(target=thread_process)
            t.start()
    except KeyboardInterrupt:
        sys.exit(0)
