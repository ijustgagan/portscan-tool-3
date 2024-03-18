import requests
import socket
import whois
import ssl
from bs4 import BeautifulSoup

def Website_info_whois(url):
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

if __name__ == "__main__":
    # Prompt the user to enter the URL
    url = input("Enter the URL of the website: ")
    
    # Call the function to get website information
    Website_info_whois(url)
