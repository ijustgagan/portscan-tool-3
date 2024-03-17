import asyncio
import aiohttp
import aiofiles
import requests
import json
import re
import time
import warnings
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from colorama import Fore, init
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import chromedriver_autoinstaller
from urllib.parse import urljoin
import socket
import threading

init()
Dgreen = Fore.LIGHTGREEN_EX
Lgreen = Fore.LIGHTGREEN_EX
Lyellw = Fore.LIGHTYELLOW_EX
Lred = Fore.LIGHTRED_EX
Lcyan = Fore.LIGHTCYAN_EX

# Call chromedriver_autoinstaller.install() before using Selenium
chromedriver_autoinstaller.install()

def banner():
    console.print(r"""
    ___       _                             
  / _ \  ___| |_ __ _ _ __   __ _ _ __ ___ 
 | | | |/ __| __/ _` | '_ \ / _` | '__/ __|
 | |_| | (__| || (_| | |_) | (_| | |  \__ \
  \___/ \___|\__\__,_| .__/ \__,_|_|  |___/
                     |_|                   
""")


async def user_finder(new_u):
    new_url2 = new_u + '/wp-json/wp/v2/users'
    headers = {"user-agent": UserAgent().random}
    async with aiohttp.ClientSession() as session:
        async with session.get(new_url2, headers=headers) as response:
            if response.status == 200:
                print(Dgreen + '\n[+] Enumerating usernames : \n')
                time.sleep(1.3)
                data = await response.json()
                for info in data:
                    print(Lgreen + ' [*] Username Found : {}'.format(info['slug']))
                    await asyncio.sleep(0.2)
            else:
                print(Lyellw + '\n[-] Usernames Not Found ')


async def adminpanel_finder(org_url):
    urlA = org_url + '/wp-login.php?action=lostpassword&error=invalidkey'
    uagent = {"user-agent": UserAgent().random}
    async with aiohttp.ClientSession() as session:
        async with session.get(urlA, headers=uagent) as response:
            if response.status == 200:
                r3data = await response.text()
                pagesoup = BeautifulSoup(r3data, 'html.parser')
                ptag = pagesoup.findAll("p", {"id": "nav"})
                if len(ptag) > 0:
                    for ptags in ptag:
                        for atags in ptags.find_all('a'):
                            if 'Log in' in atags:
                                admin_url = atags['href']
                            else:
                                print(Lyellw + '\n[-] Admin panel not found ')
                    print(Lgreen + '\n[+] Admin panel found - ', admin_url)
                else:
                    print(Lyellw + '\n[-] Admin panel not found ')
            else:
                print(Lyellw + '\n[-] Admin panel not found ')


async def xss_search():
    # Prompt the user to input the URL and payloads file path
    url = input("Enter the URL with parameter as ={xss}: ")
    payloads_file = input("Enter the path to the payloads file: ")

    # Starting XSSearch
    print("[*] Starting XSSearch ...")

    # Configuring options for Chrome WebDriver
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-xss-auditor')
    options.add_argument('--disable-web-security')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')

    # Launching Chrome WebDriver
    driver = webdriver.Chrome(options=options)

    # Executing a loop for checking valid XSS payload in the given URL
    tasks = []
    for payload in open(payloads_file, 'r', encoding='utf-8').readlines():
        task = asyncio.create_task(check_payload(url, payloads_file, payload, driver))
        tasks.append(task)

    await asyncio.gather(*tasks)

    # Closing Chrome WebDriver
    driver.close()


async def check_payload(url, payloads_file, payload, driver):
    url_with_payload = url.replace('{xss}', payload.strip())
    driver.get(url_with_payload)

    try:
        WebDriverWait(driver, 1).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.accept()
        print("\033[31m[+] XSS Triggered !\033[0m", payload.strip())
    except TimeoutException:
        print("\033[36m[+] XSS not Triggered ! \033[0m", payload.strip())


# Define the get_forms function here
def get_forms(url):
    s = requests.Session()
    s.headers["User-Agent"] = UserAgent().random
    response = s.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")


def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm


def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the character string",
              "you have an error in your SQL syntax"
              }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False


def run_sql_injection_scan():
    url = input("Enter the URL to be checked: ")
    payload_file = input("Enter the path to the payload file: ")

    try:
        with open(payload_file, 'r', encoding='utf-8') as file:
            payloads = file.readlines()
    except OSError as e:
        print("Error:", e)
        return

    warnings.filterwarnings('ignore')
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)

        for payload in payloads:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + payload.strip()
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{payload.strip()}"

            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)

            if vulnerable(res):
                print("SQL injection attack vulnerability in link:", url)
                break  # Exit the loop once vulnerability is found
        else:
            print("No SQL injection attack vulnerability detected")
            break  # Exit the loop if no vulnerability found after trying all payloads


async def run_wordpress_enumeration():
    print(Dgreen + '\nWebsite Url (with https://) : ' + Lgreen, end="")
    url = input('')
    org_url = url
    roboturl = url + '/robots.txt'
    feedurl = url + '/feed'
    rssurl = url + '/rss'
    url = url + '/wp-json'

    headers = {"user-agent": UserAgent().random}

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

                print(Dgreen + '\n[+] Webite name        :', Lgreen + siteName)
                time.sleep(0.8)
                print(Dgreen + '\n[+] Webite description :', Lgreen + siteDesc)
                time.sleep(0.8)
                print(Dgreen + '\n[+] Enumerating Plugins :', end=' ')
                plugins = list(set(plugins))
                print('\n')
                for i in plugins:
                    elem = (i[:i.find('/')])
                    print(Lgreen + ' [*] ', elem)
                    time.sleep(0.2)

                time.sleep(1)
                await adminpanel_finder(org_url)
                time.sleep(1)
                await user_finder(org_url)

            else:
                print(Dgreen + '\n[+] WordPress Detection : ', Lred + 'No')
        else:
            print(Dgreen + '\nWebsite status : ', Lred + 'Down' + r.reason)

    print(Lcyan + '')
    input('[ Thank you for using my tool ]')


async def run_port_scan():
    usage = "Usage: python3 scan.py"

    print("-" * 70)
    print("Port Scanner")
    print("-" * 70)

    target = input("Enter the target IP address or domain name: ")
    start_port = int(input("Enter the start port number: "))
    end_port = int(input("Enter the end port number: "))

    print("Scanning target", target)

    open_ports = []

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)  # Set timeout for socket connection
            conn = s.connect((target, port))
            s.close()
            open_ports.append(port)
            print("Port {} is open".format(port))
        except socket.error:
            pass  # Port is closed

    # Limit the number of concurrent threads to avoid overwhelming the target or local machine
    MAX_THREADS = 100
    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

        # Wait for threads to finish if the maximum number of threads is reached
        if len(threads) >= MAX_THREADS:
            for t in threads:
                t.join()
            threads = []

    # Wait for remaining threads to finish
    for t in threads:
        t.join()

    if not open_ports:
        print("No open ports found.")
    else:
        print("Open ports:", open_ports)

    print("Scan completed")



async def main():
    print("Choose the tool you want to use:")
    print("1. WordPress Enumeration")
    print("2. XSS Search")
    print("3. SQL Injection Scanner")
    print("4. Port Scanner")

    choice = input("Enter your choice (1/2/3/4): ")

    if choice == "1":
        await run_wordpress_enumeration()
    elif choice == "2":
        await xss_search()
    elif choice == "3":
        run_sql_injection_scan()
    elif choice == "4":
        await run_port_scan()
    else:
        print("Invalid choice. Please enter '1', '2', or '3'.")


if __name__ == "__main__":
    asyncio.run(main())
