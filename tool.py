import asyncio
import aiohttp
import aiofiles
import requests
import whois
import ssl
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
from random import randint

init()
Dgreen = Fore.LIGHTGREEN_EX
Lgreen = Fore.LIGHTGREEN_EX
Lyellw = Fore.LIGHTYELLOW_EX
Lred = Fore.LIGHTRED_EX
Lcyan = Fore.LIGHTCYAN_EX


# Define user-agent list
user_agent_list = ["Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 7.0; SM-G892A Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; SM-G935S Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 5.1.1; SM-G928X Build/LMY47X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.83 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 7.1.1; G8231 Build/41.2.A.0.219; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/59.0.3071.125 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; E6653 Build/32.2.A.0.253) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0; HTC One X10 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/61.0.3163.98 Mobile Safari/537.36","Mozilla/5.0 (Linux; Android 6.0; HTC One M9 Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.98 Mobile Safari/537.3","Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1","Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/69.0.3497.105 Mobile/15E148 Safari/605.1","Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15","Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1","Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1","Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A5370a Safari/604.1","Mozilla/5.0 (iPhone9,3; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1","Mozilla/5.0 (iPhone9,4; U; CPU iPhone OS 10_0_1 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1","Mozilla/5.0 (Apple-iPhone7C2/1202.466; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3","Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254","Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; RM-1127_16056) AppleWebKit/537.36(KHTML, like Gecko) Chrome/42.0.2311.135 Mobile Safari/537.36 Edge/12.10536","Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.1058","Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; SGP771 Build/32.2.A.0.253; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.98 Safari/537.36","Mozilla/5.0 (Linux; Android 6.0.1; SHIELD Tablet K1 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/55.0.2883.91 Safari/537.36","Mozilla/5.0 (Linux; Android 7.0; SM-T827R4 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.116 Safari/537.36","Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T550 Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.3 Chrome/38.0.2125.102 Safari/537.36","Mozilla/5.0 (Linux; Android 4.4.3; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/47.1.79 like Chrome/47.0.2526.80 Safari/537.36","Mozilla/5.0 (Linux; Android 5.0.2; LG-V410/V41020c Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/34.0.1847.118 Safari/537.36","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246","Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36","Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1","Mozilla/5.0 (CrKey armv7l 1.5.16041) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.0 Safari/537.36","Roku4640X/DVP-7.70 (297.70E04154A)","Mozilla/5.0 (Linux; U; Android 4.2.2; he-il; NEO-X5-116A Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30","Mozilla/5.0 (Linux; Android 5.1; AFTS Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/41.99900.2250.0242 Safari/537.36","Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player Build/MMB29T)","AppleTV6,2/11.1","AppleTV5,3/9.1.1","Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko) NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US","Mozilla/5.0 (Windows NT 10.0; Win64; x64; XBOX_ONE_ED) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393","Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586","Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)","Mozilla/5.0 (PlayStation Vita 3.61) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2","Mozilla/5.0 (Nintendo 3DS; U; ; en) Version/1.7412.EU","Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)","Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)","Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)","Mozilla/5.0 (X11; U; Linux armv7l like Android; en-us) AppleWebKit/531.2+ (KHTML, like Gecko) Version/5.0 Safari/533.2+ Kindle/3.0+","Mozilla/5.0 (Linux; U; en-US) AppleWebKit/528.5+ (KHTML, like Gecko, Safari/528.5+) Version/4.0 Kindle/3.0 (screen 600x800; rotate)"]

# Call chromedriver_autoinstaller.install() before using Selenium
chromedriver_autoinstaller.install()

RANDOM_USER_AGENT = user_agent_list[randint(0, len(user_agent_list) - 1)]

def banner():
    print(r"""
    ___       _                             
  / _ \  ___| |_ __ _ _ __   __ _ _ __ ___ 
 | | | |/ __| __/ _` | '_ \ / _` | '__/ __|
 | |_| | (__| || (_| | |_) | (_| | |  \__ \
  \___/ \___|\__\__,_| .__/ \__,_|_|  |___/
                     |_|                   
""")


def user_finder(new_u):
    new_url2 = new_u + '/wp-json/wp/v2/users'
    headers = {"user-agent": RANDOM_USER_AGENT}  # Insert random user-agent into headers
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

            if 'res' in locals() and vulnerable(res):  # Check if 'res' is defined and not None
                print("SQL injection attack vulnerability in link:", url)
                break  # Exit the loop once vulnerability is found
        else:
            print("No SQL injection attack vulnerability detected")
            break  # Exit the loop if no vulnerability found after trying all payloads



# async def run_wordpress_enumeration():
#     print(Dgreen + '\nWebsite Url (with https://) : ' + Lgreen, end="")
#     url = input('')
#     org_url = url
#     roboturl = url + '/robots.txt'
#     feedurl = url + '/feed'
#     rssurl = url + '/rss'
#     url = url + '/wp-json'

#     headers = {"user-agent": UserAgent().random}

#     try:
#         testreq = requests.get(org_url, headers=headers)
#     except Exception as e:
#         print(Lred + '\nWebsite status : Error !')
#     else:
#         r = requests.get(url, headers=headers)
#         rcode = r.status_code

#         if rcode == 200:
#             print(Dgreen + '\nWebsite status : ', Lgreen + 'Up')
#             robotres = requests.get(roboturl, headers=headers)
#             feedTXT = requests.get(feedurl, headers=headers).text
#             rssTXT = requests.get(rssurl, headers=headers).text

#             if 'wp-admin' in robotres.text or 'wordpress.org' in feedTXT or 'wordpress.org' in rssTXT:
#                 print(Dgreen + '\n[+] WordPress Detection : ', Lgreen + 'Yes')
#                 feedres = requests.get(feedurl, headers=headers)
#                 contents = feedres.text
#                 soup = BeautifulSoup(contents, 'xml')
#                 wpversion = soup.find_all('generator')
#                 if len(wpversion) > 0:
#                     wpversion = re.sub('<[^<]+>', "", str(wpversion[0])).replace('https://wordpress.org/?v=', '')
#                     print(Dgreen + '\n[+] WordPress version : ', Lgreen + wpversion)
#                 else:
#                     rnew = requests.get(org_url, headers=headers)
#                     if rnew.status_code == 200:
#                         newsoup = BeautifulSoup(rnew.text, 'html.parser')
#                         generatorTAGS = newsoup.find_all('meta', {"name": "generator"})
#                         for metatags in generatorTAGS:
#                             if "WordPress" in str(metatags):
#                                 altwpversion = metatags['content']
#                                 altwpversion = str(altwpversion).replace('WordPress', '')
#                                 print(Dgreen + '\n[+] WordPress version : ', Lgreen + altwpversion)
#                     else:
#                         print(Lyellw + '[-] WordPress version : Not Found !')
#                 time.sleep(0.8)

#                 data = json.loads(r.text)
#                 siteName = data['name']
#                 siteDesc = data['description']
#                 plugins = data['namespaces']

#                 print(Dgreen + '\n[+] Webite name        :', Lgreen + siteName)
#                 time.sleep(0.8)
#                 print(Dgreen + '\n[+] Webite description :', Lgreen + siteDesc)
#                 time.sleep(0.8)
#                 print(Dgreen + '\n[+] Enumerating Plugins :', end=' ')
#                 plugins = list(set(plugins))
#                 print('\n')
#                 for i in plugins:
#                     elem = (i[:i.find('/')])
#                     print(Lgreen + ' [*] ', elem)
#                     time.sleep(0.2)

#                 time.sleep(1)
#                 await adminpanel_finder(org_url)
#                 time.sleep(1)
#                 await user_finder(org_url)

#             else:
#                 print(Dgreen + '\n[+] WordPress Detection : ', Lred + 'No')
#         else:
#             print(Dgreen + '\nWebsite status : ', Lred + 'Down' + r.reason)

#     print(Lcyan + '')
#     input('[ Thank you for using my tool ]')


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

async def Website_info_whois(url):
    # Send a GET request to the URL
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return
    
    
    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the website
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract information from the website
        title = soup.title.string
        meta_tags = soup.find_all('meta')
        links = [link.get('href') for link in soup.find_all('a')]
        text_content = soup.get_text()
        
        # Get IP address of the website
        try:
            ip_address = socket.gethostbyname(url.split("//")[-1].split("/")[0])
        except socket.gaierror:
            print("Failed to resolve IP address.")
            ip_address = None
        
        # Get WHOIS information
        try:
            domain_info = whois.whois(url)
        except whois.parser.PywhoisError:
            print("Failed to retrieve WHOIS information.")
            domain_info = None
        
        # Get SSL certificate information
        try:
            cert = ssl.get_server_certificate((url.split("//")[-1].split("/")[0], 443))
            x509 = ssl.PEM_cert_to_DER_cert(cert)
            cert_info = ssl.DER_cert_to_PEM_cert(x509)
        except Exception as e:
            print("Failed to retrieve SSL certificate information:", e)
            cert_info = None
        
        # Get response headers
        headers = response.headers
        
        # Print the extracted information
        print("Title:", title)
        print("\nMeta Tags:")
        for tag in meta_tags:
            print(tag.get('name'), ":", tag.get('content'))
        
        print("\nLinks:")
        for link in links:
            print(link)
        
        print("\nText Content:")
        print(text_content)
        
        print("\nIP Address:", ip_address)
        print("\nWHOIS Information:")
        print(domain_info)
        print("\nSSL Certificate Information:")
        print(cert_info)
        print("\nResponse Headers:")
        for header, value in headers.items():
            print(header + ":", value)
    else:
        print("Failed to retrieve website information.")



async def main():
    print("Choose the tool you want to use:")
    # print("1. WordPress Enumeration")
    print("1. XSS Search")
    print("2. SQL Injection Scanner")
    print("3. Port Scanner")
    print("4. Website Information Whois")

    choice = input("Enter your choice (1/2/3/4): ")

    # if choice == "1":
    #     await run_wordpress_enumeration()
    if choice == "1":
        await xss_search()
    elif choice == "2":
        run_sql_injection_scan()
    elif choice == "3":
        await run_port_scan()
    elif choice == "4":
        url = input("Enter the URL of the website: ")
        await Website_info_whois(url)
    else:
        print("Invalid choice. Please enter '1', '2', '3', or '4'.")


if __name__ == "__main__":
    banner()
    asyncio.run(main())
