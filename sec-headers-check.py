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
        # prepend http if missing
        parsed_url = parsed_url._replace(**{"scheme": "http"})
        parsed_url = parsed_url._replace(**{"netloc": parsed_url[2]})  # move path to netloc
        parsed_url = parsed_url._replace(**{"path": ""})
        # check again with fixed url
        if not (checkers.is_url(parsed_url.geturl()) or checkers.is_ip_address(parsed_url.geturl())):
            return False
    return True


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', dest='url', metavar='URL', required=True, help='URL https://example.com')
    parser.add_argument('--verify', action='store_true', default=False, help='Verify the SSL certificate. Default is set to False.')
    parser.add_argument('--description', action='store_true', help='Print header description')

    args = parser.parse_args()
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Cache-control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'close'
    })

    # prepend http if missing
    args.url = 'http://' + args.url if not args.url.startswith('http') else args.url
    if not valid_url(args.url):
        parser.print_help()
        exit()

    try:
        response = session.get(url=args.url, verify=args.verify)
    except requests.exceptions.ConnectionError as e:
        print(bold(bad(f"{bold(red('connection error'))}: {e}")))
        print(bold(bad(f'{args.url}')))
        exit()
    except Exception:
        print(bold(bad(bold(red('connection error')))))
        print(bold(bad(f'{args.url}')))
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

    descriptions = {}
    descriptions['X-Content-Type-Options'] = que('X-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. The only valid value for this header is "X-Content-Type-Options: nosniff".')
    descriptions['X-Frame-Options'] = que('X-Frame-Options tells the browser whether you want to allow your site to be framed or not. By preventing a browser from framing your site you can defend against attacks like clickjacking.')
    descriptions['X-XSS-Protection'] = que('X-XSS-Protection sets the configuration for the XSS Auditor built into older browser. The recommended value was "X-XSS-Protection: 1; mode=block" but you should now look at Content Security Policy instead.')
    descriptions['Strict-Transport-Security'] = que('HTTP Strict Transport Security is an excellent feature to support on your site and strengthens your implementation of TLS by getting the User Agent to enforce the use of HTTPS.')
    descriptions['Content-Security-Policy'] = que('Content Security Policy is an effective measure to protect your site from XSS attacks. By whitelisting sources of approved content, you can prevent the browser from loading malicious assets. Analyse this policy in more detail. You can sign up for a free account on Report URI to collect reports about problems on your site.')
    descriptions['Referrer-Policy'] = que('Referrer-Policy Referrer Policy is a new header that allows a site to control how much information the browser includes with navigations away from a document and should be set by all sites.')
    descriptions['Feature-Policy'] = que('Feature Policy is a new header that allows a site to control which features and APIs can be used in the browser.')

    cookie_checks = [
        'Expires',
        'HttpOnly',
        'Secure',
        'Path=/',
    ]

    print(info(f"{bold('Request URL')}: {args.url}"))
    print(info(f"{bold('Response status code')}: {response.status_code}"))

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
            if args.description:
                if check_head in descriptions.keys():
                    print(descriptions[check_head])

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
