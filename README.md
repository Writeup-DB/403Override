<img width="500" height="250" alt="image" src="https://github.com/user-attachments/assets/b2a819b6-548d-4038-9fe1-78204dd84a33" />

# 403Override: Bypass Restricted Access

403Override is a powerful cybersecurity tool designed to bypass HTTP 403 Forbidden responses, enabling secure access to restricted resources. Whether you're a penetration tester, security researcher, or ethical hacker, 403Override empowers you to navigate through web application defenses with ease. This tool leverages advanced techniques to bypass access controls, uncover hidden content, and test the robustness of security implementations. With its user-friendly interface and robust functionality, 403Override is an essential addition to any cybersecurity toolkit, helping you ensure comprehensive security assessments and discover vulnerabilities that others might miss.

Built with Python's asyncio and aiohttp, it allows for rapid testing of hundreds of header and path combinations while maintaining a low footprint.

- ## ✨ Features

* **⚡ High-Speed Asynchronous Engine**: Powered by `aiohttp` for non-blocking concurrent requests.
* **📊 Pro Dashboard**: Real-time progress bars and color-coded results using the `Rich` library.
* **🎯 Intelligent Baselines**: Automatically establishes a baseline response to highlight **Size Diffs** and **Status Changes**.
* **🛡️ WAF Evasion**: Built-in **Auto-Throttle** (delay) and **Proxy Support** (HTTP/SOCKS) to bypass rate limits.
* **🔐 Auth Support**: Test authenticated vs. unauthenticated bypasses simultaneously with the `--cookies` and `--unauth` flags.
* **🔍 Advanced Filtering**: Use `--hide-size` to suppress noise and `--grep` to find specific strings in response bodies.
* **📄 Multi-Format Reporting**: Export results to **JSON**, **CSV**, or a **Self-Contained Interactive HTML Dashboard**.
* **Directory and URL Scanning**: Scan specified URLs and directories for access issues.
* **Custom Headers**: Test with various custom headers and payloads.

## Installation

To use `403bypasser`, ensure you have Python 3.7 or later installed. You can install the necessary dependencies using `pip`.

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/403bypasser.git
cd 403bypasser
```

2. Install Dependencies
```bash

pip install -r requirements.txt
or 
pip install aiohttp aiohttp_proxy validators tldextract rich jinja2 pyfiglet colorama aiofiles
```

## Configuration (Wordlists)
The tool looks for two optional text files in the root directory. If not found, it uses internal defaults.
- headers.txt: One header per line (e.g., X-Forwarded-For).
- ip_address.txt: One value per line (e.g., 127.0.0.1, localhost, 0x7F000001).

## Usage
Command-Line Arguments
- -u or --url: Specify a single URL to scan (e.g., http://example.com).
- -U or --urllist: Provide a path to a file containing a list of URLs (e.g., urllist.txt).
- -d or --dir: Provide a single directory to scan (e.g., /admin).
- -D or --dirlist: Provide a path to a file containing a list of directories (e.g., dirlist.txt).
- -o or --output: Specify the output format. Use txt for text format (default) or json for JSON format.

## 📖 Usage Examples
### Basic Scan
Scan a single directory for common bypasses:
```bash
python 403bypasser.py -u http://example.com
```

### Authenticated Bypass Testing
Test if your session cookies allow you to bypass restrictions, while also checking the unauthenticated state:
```bash
python 403Override.py -u [https://example.com](https://example.com) -d /admin --cookies "session=123; user=admin" --unauth
```

### Bug Bounty Workflow (WAF Evasion + Reporting)
Tunnel traffic through Burp Suite, hide the "noise" (baseline 403s), use a delay to avoid bans, and generate an HTML report:
```bash
python 403Override.py -u [https://example.com](https://example.com) -d /admin --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080) --delay 500 --hide-size --html
```

### Searching for Sensitive Data
Search for the string "root:" across a list of URLs:
```bash
python 403Override.py -U urls.txt -d /etc/passwd --grep "root:" --json
```

## ⚙️ Arguments Reference

```base
-u, --url	Single target URL.
-U, --urllist	Path to a file containing a list of URLs.
-d, --dir	The restricted directory to test (default: /).
-t, --threads	Number of concurrent requests (default: 5).
-c, --cookies	HTTP Cookie string for authenticated scans.
--unauth	Runs an unauthenticated scan even if cookies are provided.
--proxy	Route traffic through a proxy (e.g., http://127.0.0.1:8080).
--delay	Delay between requests in milliseconds (Auto-Throttle).
--baseline	Sets a reference point for size/status comparison (Default: True).
--hide-size	Hides any result that matches the baseline response size.
--soft	Flag any result where the status code differs from the baseline.
--grep	Highlights responses containing a specific string.
--html / --json / --csv	Save the results to the specified file format
```

## 📊 Understanding Results
When the scan completes, pay attention to the Note column in the CLI or the HTML report:
- Size Diff: The server returned a 403, but the page content size is different from the standard error page. This often indicates a partial bypass or a different error message.
- Status Change: The server returned something other than the baseline (e.g., 401 instead of 403).
- [Grep Hit]: Your specified string (via --grep) was found in the response body.
- SUCCESS?: A 2xx status code was returned.


## 📜 License
This project is licensed under the MIT License.

Disclaimer: This tool is for educational purposes and authorized security testing only. The author is not responsible for any misuse or damage caused by this tool.

For any questions or issues, please open an issue on the GitHub repository.
`Feel free to adjust any specific details such as repository URLs or additional information as needed`