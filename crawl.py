import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def fetch_robots_txt(url):
    robots_url = urljoin(url, '/robots (1).txt')
    response = requests.get(robots_url)
    if response.status_code == 200:
        return response.text
    else:
        return None

def fetch_sitemap(url):
    sitemap_url = urljoin(url, '/sitemap.xml')
    response = requests.get(sitemap_url)
    if response.status_code == 200:
        return response.text
    else:
        return None

if __name__ == "__main__":
    url = input("Enter the URL to crawl: ")

    robots_txt = fetch_robots_txt(url)
    if robots_txt:
        print("Robots.txt content:")
        print(robots_txt)
    else:
        print("Failed to fetch robots.txt")

    sitemap_xml = fetch_sitemap(url)
    if sitemap_xml:
        print("Sitemap.xml content:")
        print(sitemap_xml)
    else:
        print("Failed to fetch sitemap.xml")
