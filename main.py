#!/usr/bin/env python3

# Author: @luadham
# Date: 2023-04-20
# Description: A Simple Web Crawler For Cyber Security Course CC536

import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse
from collections import deque
import concurrent.futures
import optparse

exclude = ['jpg', 'png', 'gif', 'pdf']

def request(target):
    if "http" not in target:
        target = "http://" + target
    try:
        return requests.get(target)
    except:
        return None


def extract_urls(target):
    res = request(target)
    if not res:
        print("[!] Make Sure You Enter A Valid URL :(")
        exit(0)
    bs = BeautifulSoup(res.content, 'html.parser')
    urls = [link['href'].strip() for link in bs.findAll('a', href=True)]
    return urls


def filter_links(links, domain):
    def filter_pipeline(link):
        return True if link.split('.')[
                           -1] not in exclude and domain in link and "#" not in link and "redirect" not in link else False

    filtered_links = { urlparse.urljoin("https://" + domain, link) for link in links if filter_pipeline(link) }

    return filtered_links


def get_links(target):
    with concurrent.futures.ThreadPoolExecutor() as excuter:
        links = excuter.submit(extract_urls, target).result()
        filter_urls = excuter.submit(filter_links, links, target).result()
        return filter_urls


def BFS(link):
    visited_urls = set()
    mails = set()
    queue = deque([link])
    with concurrent.futures.ThreadPoolExecutor() as exector:
        while queue:
            url = queue.popleft()
            if not request(url):
                continue
            if "mailto" in url:
                mails.add(url)
                continue
            print(url)
            urls = exector.submit(get_links, url).result()
            for url in urls:
                if url not in visited_urls and url not in queue:
                    visited_urls.add(url)
                    queue.append(url)
        return visited_urls, mails

def preprocess_target(target):
    if target[-1] == '/':
        target = target[:-1]

    if "http" not in target:
        target = "https://" + target

    _, domain = target.split('://')
    return domain

def write_output(visited_urls, mails):
    with open("output.txt", "w") as f:
        f.write("Visited URLs:\n")
        for url in visited_urls:
            f.write(url)
            f.write("\n")
        f.write("Mails:\n")
        for mail in mails:
            f.write(mail)
            f.write("\n")

if __name__ == '__main__':
    try:
        parser = optparse.OptionParser()
        
        parser.add_option('-t', '--target', dest='target', help='Target URL')
        
        (options, args) = parser.parse_args()

        if not options.target:
            print("[!] Please Enter A Target URL :(")
            exit(0)
        
        target = options.target
        domain = preprocess_target(target)
        visited_urls, mails = BFS(domain)
        write_output(visited_urls, mails)

    except KeyboardInterrupt:
        print("[!] Exiting ...")
        exit(0)