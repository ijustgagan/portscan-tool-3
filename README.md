# OctaparsTool

## Description
This toolkit provides various tools for web security testing, including WordPress enumeration, XSS (Cross-Site Scripting) search, SQL injection scanning, and port scanning.

## Environment Setup
1. **Install Python and pip:**
    ```bash
    sudo apt update
    sudo apt install python3 python3-pip
    ```

2. **Create a virtual environment:**
    ```bash
    python3 -m venv myenv
    source myenv/bin/activate
    ```

3. **Clone the OctaparsTOOl repository:**
    ```bash
    git clone https://github.com/ijustgagan/Octapars_tool.git
    cd Octapars_tool
    ```

4. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Activate the virtual environment:**
    ```bash
    source myenv/bin/activate
    ```

2. **Navigate to the project directory:**
    ```bash
    cd OctaparsTOOl
    ```

3. **Run the `tool.py` script:**
    ```bash
    python3 tool.py
    ```

4. **Choose the tool you want to use by entering the corresponding number:**
    - 1: WordPress Enumeration
    - 2: XSS Search
    - 3: SQL Injection Scanner
    - 4: Port Scanner

5. **Follow the prompts and input any required information.**

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
