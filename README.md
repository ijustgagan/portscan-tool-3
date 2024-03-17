# OctaparsTOOl

## Description
This toolkit provides various tools for web security testing, including WordPress enumeration, XSS (Cross-Site Scripting) search, SQL injection scanning, and port scanning.

## Installation
1. Install Python (if not already installed) from [python.org](https://www.python.org/downloads/).
2. Install required Python packages using pip:
    ```
    pip install aiohttp aiofiles requests fake_useragent beautifulsoup4 selenium chromedriver-autoinstaller colorama
    ```
3. Install Chrome WebDriver using chromedriver-autoinstaller:
    ```python
    import chromedriver_autoinstaller
    chromedriver_autoinstaller.install()
    ```
4. Clone or download this repository to your local machine.

## Usage
1. Open a terminal or command prompt.
2. Navigate to the directory where the toolkit is located.
3. Run the `main.py` script:
    ```
    python main.py
    ```
4. Choose the tool you want to use by entering the corresponding number:
    - 1: WordPress Enumeration
    - 2: XSS Search
    - 3: SQL Injection Scanner
    - 4: Port Scanner
5. Follow the prompts and input any required information.

### WordPress Enumeration
- Enter the website URL (with https://).
- Follow the prompts to complete the enumeration process.

### XSS Search
- Enter the URL with the parameter `{xss}`.
- Enter the path to the payloads file containing XSS payloads.

### SQL Injection Scanner
- Enter the URL to be checked.
- Enter the path to the payload file containing SQL injection payloads.

### Port Scanner
- Enter the target IP address or domain name.
- Enter the start and end port numbers to scan.

## Contributors
- [Gagan]

---

You can customize the README further based on your preferences and add any additional information or instructions as needed.