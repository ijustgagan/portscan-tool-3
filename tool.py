# Importing necessary libraries
import socket
import requests
import json
import re
import time
from threading import Thread, Lock
from queue import Queue
from bs4 import BeautifulSoup
from colorama import Fore, init
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from rich.console import Console
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import warnings
import argparse
import sys
from datetime import datetime

# Initialization
init()
Dgreen = Fore.LIGHTGREEN_EX
Lgreen = Fore.LIGHTGREEN_EX
Lyellw = Fore.LIGHTYELLOW_EX
Lred = Fore.LIGHTRED_EX
Lcyan = Fore.LIGHTCYAN_EX
print_lock = Lock()

# HolyScan global variables
console = Console()
N_Thread = 200
q = Queue()

#banner
def banner():
    console.print(r"""
    ___       _                             
  / _ \  ___| |_ __ _ _ __   __ _ _ __ ___ 
 | | | |/ __| __/ _` | '_ \ / _` | '__/ __|
 | |_| | (__| || (_| | |_) | (_| | |  \__ \
  \___/ \___|\__\__,_| .__/ \__,_|_|  |___/
                     |_|                   
""")
# Website Scanner
def user_finder(new_u):
    new_url2 = new_u + '/wp-json/wp/v2/users'
    user_agent_rotator = UserAgent(software_names=[SoftwareName.CHROME.value], operating_systems=[OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value], limit=100)
    headers = {"User-Agent": user_agent_rotator.get_random_user_agent()}

    r2 = requests.get(new_url2, headers=headers)

    if r2.status_code == 200:
        print(Dgreen + '\n[+] Enumerating usernames : \n')
        time.sleep(1.3)
        data = json.loads(r2.text)
        for info in data:
            print(Lgreen + ' [*] Username Found : {}'.format(info['slug']))
            time.sleep(0.2)
    else:
        print(Lyellw + '\n[-] Usernames Not Found ')

# XSS Scanner
def xss_scanner(target, p):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-xss-auditor')
    options.add_argument('--disable-web-security')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(executable_path='/usr/bin/chromedriver', chrome_options=options)
    print("\n[*] Starting XSSearch ...")
    for payload in open(p, 'r').readlines():
        url = target.replace('{xss}', payload)
        driver.get(url)
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            print("\033[31m[+] XSS Triggered !\033[0m", payload)
        except TimeoutException:
            print("\033[36m[+] XSS not Triggered ! \033[0m", payload)
    driver.close()

# Port Scanner
def portscan(port):
    try:
        s = socket.socket()
        s.connect((host, port))
    except:
        with print_lock:
            pass
    else:
        with print_lock:
            serviceName = socket.getservbyport(port)
            service = serviceName.upper()
            console.print(f"\t- {service}: {port}")
    finally:
        s.close()

def scan_thread():
    global q
    while True:
        worker = q.get()
        portscan(worker)
        q.task_done()

def scanner(host, ports):
    global q
    for t in range(N_Thread):
        t = Thread(target=scan_thread)
        t.daemon = True
        t.start()
    for worker in ports:
        q.put(worker)
    q.join()

# Main function
if __name__ == '__main__':
    banner()
    print(Dgreen + '\nWebsite Url (with https://) : ' + Lgreen, end="")
    url = input('')
    org_url = url
    roboturl = url + '/robots.txt'
    feedurl = url + '/feed'
    rssurl = url + '/rss'
    url = url + '/wp-json'
    headers = {"user-agent": UserAgent().get_random_user_agent()}
    try:
        testreq = requests.get(org_url, headers=headers)
    except Exception as e:
        print(Lred + '\nWebsite status : Error !')
    else:
        r = requests.get(url, headers=headers)
        rcode = r.status_code
        if rcode == 200:
            print(Dgreen + '\nWebsite status : ', Lgreen + 'Up')
            robotres = requests.get(roboturl, headers=headers)
            feedTXT = requests.get(feedurl, headers=headers).text
            rssTXT = requests.get(rssurl, headers=headers).text
            if 'wp-admin' in robotres.text or 'wordpress.org' in feedTXT or 'wordpress.org' in rssTXT:
                print(Dgreen + '\n[+] WordPress Detection : ', Lgreen + 'Yes')
                feedres = requests.get(feedurl, headers=headers)
                contents = feedres.text
                soup = BeautifulSoup(contents, 'xml')
                wpversion = soup.find_all('generator')
                if len(wpversion) > 0:
                    wpversion = re.sub('<[^<]+>', "", str(wpversion[0])).replace('https://wordpress.org/?v=', '')
                    print(Dgreen + '\n[+] WordPress version : ', Lgreen + wpversion)
                else:
                    rnew = requests.get(org_url, headers=headers)
                    if rnew.status_code == 200:
                        newsoup = BeautifulSoup(rnew.text, 'html.parser')
                        generatorTAGS = newsoup.find_all('meta', {"name": "generator"})
                        for metatags in generatorTAGS:
                            if "WordPress" in str(metatags):
                                altwpversion = metatags['content']
                                altwpversion = str(altwpversion).replace('WordPress', '')
                                print(Dgreen + '\n[+] WordPress version : ', Lgreen + altwpversion)
                    else:
                        print(Lyellw + '[-] WordPress version : Not Found !')
                time.sleep(0.8)
                data = json.loads(r.text)
                siteName = data['name']
                siteDesc = data['description']
                plugins = data['namespaces']
                print(Dgreen + '\n[+] Website name        :', Lgreen + siteName)
                time.sleep(0.8)
                print(Dgreen + '\n[+] Website description :', Lgreen + siteDesc)
                time.sleep(0.8)
                print(Dgreen + '\n[+] Enumerating Plugins :', end=' ')
                plugins = list(set(plugins))
                print('\n')
                for i in plugins:
                    elem = (i[:i.find('/')])
                    print(Lgreen + ' [*] ', elem)
                    time.sleep(0.2)
                time.sleep(1)
                adminpanel_finder(org_url)
                time.sleep(1)
                user_finder(org_url)
            else:
                print(Dgreen + '\n[+] WordPress Detection : ', Lred + 'No')
        else:
            print(Dgreen + '\nWebsite status : ', Lred + 'Down' + r.reason)
    print(Lcyan + '')
    input('[ Thank you for using my tool ]')
