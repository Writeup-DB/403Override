import os
import sys
import argparse
import validators
import tldextract
import asyncio
import aiohttp
import json
from colorama import init, Fore, Style
from pyfiglet import Figlet
from aiofiles import open as aio_open
from datetime import datetime

# Initialize Colorama
init()

# Display Banner -- Start
custom_fig = Figlet(font='slant')
print(Fore.BLUE + Style.BRIGHT + custom_fig.renderText('403Override') + Style.RESET_ALL)
print(Fore.GREEN + Style.BRIGHT + "____________________ Version 1.0.1 ____________________\n")
# Display Banner -- End

# Handle Arguments -- Start
parser = argparse.ArgumentParser(description="403Override Scanner")
parser.add_argument("-u", "--url", type=str, help="Single URL to scan, ex: http://example.com")
parser.add_argument("-U", "--urllist", type=str, help="Path to list of URLs, ex: urllist.txt")
parser.add_argument("-d", "--dir", type=str, help="Single directory to scan, ex: /admin", nargs="?", const="/")
parser.add_argument("-D", "--dirlist", type=str, help="Path to list of directories, ex: dirlist.txt")
parser.add_argument("-o", "--output", type=str, help="Output format: text (default) or json", default="text")
args = parser.parse_args()
# Handle Arguments -- End

class Arguments:
    def __init__(self, url, urllist, dir, dirlist):
        self.url = url
        self.urllist = urllist
        self.dir = dir
        self.dirlist = dirlist
        self.output_format = args.output.lower()
        self.urls = []
        self.dirs = []

        self.check_url()
        self.check_dir()

    def check_url(self):
        if self.url:
            if not validators.url(self.url):
                print(Fore.RED + "You must specify a valid URL for -u (--url) argument! Exiting...\n" + Style.RESET_ALL)
                sys.exit(1)

            self.url = self.url.rstrip("/")
            self.urls.append(self.url)
        elif self.urllist:
            if not os.path.exists(self.urllist):
                print(Fore.RED + "The specified path to URL list does not exist! Exiting...\n" + Style.RESET_ALL)
                sys.exit(1)

            with open(self.urllist, 'r') as file:
                self.urls = [line.strip() for line in file if validators.url(line.strip())]
        else:
            print(Fore.RED + "Please provide a single URL or a list of URLs! (-u or -U)\n" + Style.RESET_ALL)
            sys.exit(1)

    def check_dir(self):
        if self.dir:
            self.dir = self.dir.rstrip("/")
            self.dirs.append(self.dir)
        elif self.dirlist:
            if not os.path.exists(self.dirlist):
                print(Fore.RED + "The specified path to directory list does not exist! Exiting...\n" + Style.RESET_ALL)
                sys.exit(1)

            with open(self.dirlist, 'r') as file:
                self.dirs = [line.strip() for line in file if line.strip()]
        else:
            self.dirs.append("/")  # Default to root path if no directory specified

class PathRepository:
    def __init__(self, path):
        self.path = path
        self.new_paths = self.create_new_paths()
        self.new_headers = self.create_new_headers()

    def create_new_paths(self):
        pairs = [["/", "//"], ["/.", "/./"]]
        leadings = ["/%2e"]
        trailings = ["/", "..;/", "/..;/", "%20", "%09", "%00",".json", ".css", ".html", "?", "??", "???","?anyparam", "#", "#anything", "/."]

        paths = [self.path]

        for pair in pairs:
            paths.append(pair[0] + self.path + pair[1])

        for leading in leadings:
            paths.append(leading + self.path)

        for trailing in trailings:
            paths.append(self.path + trailing)

        return paths

    def create_new_headers(self):
        headers_overwrite = ["X-Original-URL", "X-Rewrite-URL"]
        headers = ["X-Custom-IP-Authorization", "X-Forwarded-For","X-Forward-For", "X-Remote-IP", "X-Originating-IP","X-Remote-Addr", "X-Client-IP", "X-Real-IP","X-Original-URL","X-Host", "Referer", "X-ProxyUser-Ip", "Client-IP", "True-Client-IP", "Cluster-Client-IP" ]
        
        values = ["localhost", "localhost:80", "localhost:443","127.0.0.1", "127.0.0.1:80", "127.0.0.1:443","2130706433", "0x7F000001", "0177.0000.0000.0001","0", "127.1", "10.0.0.0", "10.0.0.1", "172.16.0.0","172.16.0.1", "192.168.1.0", "192.168.1.1","0177.0.0.1","127.0.1","169.254-169.254"]

        new_headers = [{header: value} for header in headers for value in values]
        rewrite_headers = [{element: self.path} for element in headers_overwrite]

        return new_headers + rewrite_headers

class Query:
    def __init__(self, url, path_repo, session, output_format):
        self.url = url
        self.path_repo = path_repo
        self.domain = tldextract.extract(self.url).domain
        self.session = session
        self.output_format = output_format
        self.results = []

    async def send_request(self, method, path, headers=None):
        try:
            async with self.session.request(method, self.url + path, headers=headers) as response:
                status = response.status
                size = len(await response.read())
                colour = self.get_status_colour(status)
                return (method, path, headers, status, size, colour)
        except Exception as e:
            print(Fore.RED + f"Request failed: {e}" + Style.RESET_ALL)
            return None

    def get_status_colour(self, status_code):
        if status_code in [200, 201]:
            return Fore.GREEN + Style.BRIGHT
        elif status_code in [301, 302]:
            return Fore.BLUE + Style.BRIGHT
        elif status_code in [403, 404]:
            return Fore.MAGENTA + Style.BRIGHT
        elif status_code == 500:
            return Fore.RED + Style.BRIGHT
        else:
            return Fore.WHITE + Style.BRIGHT

    def format_output(self, result):
        method, path, headers, status, size, colour = result
        header_info = f" Header={headers}" if headers else ""
        line_width = 100
        target_address = f"{method} --> {self.url}{path}"
        info = f"STATUS: {colour}{status}{Style.RESET_ALL}\tSIZE: {size}"
        remaining = line_width - len(target_address)
        return target_address + " " * remaining + info + header_info

    def format_json(self, result):
        method, path, headers, status, size, _ = result
        return {
            "method": method,
            "path": self.url+path,
            "headers": headers if headers else None,
            "status": status,
            "size": size
        }

    async def run(self):
        tasks = []

        print(f"\n{(' Target URL: ' + self.url + ' ').center(41, '=')}")
        print("="*50)
        
        # Initial POST request
        tasks.append(self.send_request('POST', self.path_repo.path))
        
        # Path manipulations
        for path in self.path_repo.new_paths:
            tasks.append(self.send_request('GET', path))
        
        # Header manipulations
        for headers in self.path_repo.new_headers:
            tasks.append(self.send_request('GET', self.path_repo.path, headers=headers))
        
        responses = await asyncio.gather(*tasks)

        # Log and display results
        for result in responses:
            if result:
                if self.output_format == "json":
                    self.results.append(self.format_json(result))
                else:
                    formatted_output = self.format_output(result)
                    print(formatted_output)
                    self.results.append(formatted_output)
        
        # Write results to file
        await self.write_to_file()

    async def write_to_file(self):
        filename = f"{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{self.output_format}"
        async with aio_open(filename, "a") as file:
            if self.output_format == "json":
                json_data = json.dumps(self.results, indent=4)
                await file.write(json_data)
                print("Result saved in : "+ filename)

            else:
                for line in self.results:
                    await file.write(line + "\n")

class Program:
    def __init__(self, urls, dirs, output_format):
        self.urls = urls
        self.dirs = dirs
        self.output_format = output_format

    async def initialise(self):
        async with aiohttp.ClientSession() as session:
            for url in self.urls:
                for dir in self.dirs:
                    path_repo = PathRepository(dir)
                    query = Query(url, path_repo, session, self.output_format)
                    await query.run()


if __name__ == "__main__":
    try:
        arguments = Arguments(args.url, args.urllist, args.dir, args.dirlist)
        program = Program(arguments.urls, arguments.dirs, arguments.output_format)
        asyncio.run(program.initialise())
    except KeyboardInterrupt:
        print(Fore.RED + "\nProcess interrupted by user. Exiting...\n" + Style.RESET_ALL)
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\nAn unexpected error occurred: {e}\n" + Style.RESET_ALL)
        sys.exit(1)