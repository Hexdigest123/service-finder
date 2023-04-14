import socket
import random
import struct
import threading
import requests
import ftplib
import sys
import smtplib
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup
import whois

SMTP_DIRECTORY_PATH = ""  # fill out this path to enable user enumeration

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
        with socket.socket() as sock:
            if sock.connect_ex((ip, 80)) == 0:
                resp = requests.get(f"http://{ip}/", timeout=5)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    if "Apache2 Ubuntu Default Page: It works" in soup.title or "Welcome to nginx!" in soup.title:
                        return False, ""
                    return True, "https"
            if sock.connect_ex((ip, 443)) == 0:
                resp = requests.get(f"https://{ip}/", timeout=5)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    if "Apache2 Ubuntu Default Page: It works" in soup.title or "Welcome to nginx!" in soup.title:
                        return False, ""
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


def scan_for_smtp(ip: str) -> [bool, str]:
    try:
        with smtplib.SMTP(ip, 587, timeout=5) as mail_server:
            mail_server.ehlo()
            mail_server.starttls()
            mail_server.ehlo()
            if SMTP_DIRECTORY_PATH and SMTP_DIRECTORY_PATH != "":
                with open(SMTP_DIRECTORY_PATH, "r") as f:
                    for line in f:
                        try:
                            split_line = line.split(";")
                            mail_server.login(split_line[0], split_line[1])
                            break
                        except smtplib.SMTPAuthenticationError:
                            continue
            else:
                mail_server.login("root", "")
            mail_server.quit()
            return True, "SMTP"
    except smtplib.SMTPAuthenticationError:
        return True, "SMTP"
    except socket.error:
        return False, ""
    except Exception as e:
        return False, ""


def scan_domain_information(ip: str) -> [bool, tuple]:
    try:
        w = whois.whois(ip)
        return True, w.domain
    except Exception as e:
        return False, ""


def thread_process():
    try:
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

            smtp_request = scan_for_smtp(ip_to_scan)
            if smtp_request[0]:
                ip_information["allowed_protocols"].append((smtp_request[1], "587"))

            if len(ip_information["allowed_protocols"]) != 0:
                print(ip_to_scan)
                for prot in ip_information["allowed_protocols"]:
                    debug_msg(f"Protocol: {prot[0]} ({prot[1]})")
                print("\n")

            whois_request = scan_domain_information(ip_to_scan)
            if whois_request[0]:
                print(f"Domain: {whois_request[1]}")
    except KeyboardInterrupt:
        sys.exit()




if __name__ == '__main__':
    try:
        for i in range(MAX_NUMBER_OF_THREADS):
            t = threading.Thread(target=thread_process)
            t.start()
    except KeyboardInterrupt:
        sys.exit(0)
