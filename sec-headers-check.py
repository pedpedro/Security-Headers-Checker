#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import re
import requests
import argparse

from urllib.parse import urlparse
from validator_collection import checkers
from bs4 import BeautifulSoup
from huepy import bold, info, run, que, bad, good, red


requests.packages.urllib3.disable_warnings()


def valid_url(url: str) -> bool:
    """Check that the URL is well formatted."""
    parsed_url = urlparse(url)
    if not (checkers.is_url(parsed_url.geturl()) or checkers.is_ip_address(parsed_url.geturl())):
        # prepend https if missing
        parsed_url = parsed_url._replace(**{"scheme": "https"})
        parsed_url = parsed_url._replace(**{"netloc": parsed_url[2]})  # move path to netloc
        parsed_url = parsed_url._replace(**{"path": ""})
        # check again with fixed url
        if not (checkers.is_url(parsed_url.geturl()) or checkers.is_ip_address(parsed_url.geturl())):
            return False
    return True


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='url', metavar='URL', required=True, help='URL https://example.com')
    parser.add_argument('--verbose', action='store_true', help='View request and response headers.')

    args = parser.parse_args()
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Cache-control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'close'
    })

    # prepend https if missing
    args.url = 'https://' + args.url if not args.url.startswith('https') else args.url
    if not valid_url(args.url):
        parser.print_help()
        exit()

    headers = response.headers
    html = response.text
    soup = BeautifulSoup(html, "lxml")

    check_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Feature-Policy'
    ]

    cookie_checks = [
        'Expires',
        'HttpOnly',
        'Secure',
        'Path=/',
    ]

    print(run(f"{bold('Request URL')}: {args.url}"))
    if response.status_code == 200:
        print(good(f"{bold('Response status code')}: {response.status_code}")) 
    elif response.status_code in [300,301,302] :
        print(info(f"{bold('Response status code')}: {response.status_code}")) 
    else:
        print(bad(f"{bold('Response status code')}: {response.status_code}")) 

    if args.verbose:
        print(info(bold('Request headers:')))
        print(json.dumps(dict(session.headers), indent=2, sort_keys=True))

        print(info(bold('Response headers:')))
        print(json.dumps(dict(headers), indent=2, sort_keys=True))

    print(f"\n{run(bold('Checking security headers...'))}")
    for check_head in check_headers:
        if check_head.lower() in headers:
            print(good(f'{check_head} found'))
        else:
            print(bad(f'{check_head} not found'))
            # if args.description:
            #     if check_head in descriptions.keys():
            #         print(descriptions[check_head])

    print(f"\n{run(bold('Checking cookies...'))}")
    if 'set-cookie' in headers:
        cookies = headers['Set-Cookie'].split(',')
        for cookie in cookies:
            print(f"{bold('cookie: ')} {cookie}")
            for cookie_check in cookie_checks:
                if cookie_check.lower() in cookie.lower():
                    print(good(f'{cookie_check} found'))
                else:
                    print(bad(f'{cookie_check} not found'))
    else:
        print(info('not found'))



if __name__ == '__main__':
    main()
