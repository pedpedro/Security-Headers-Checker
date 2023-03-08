import json
import re
import requests
import argparse

from urllib.parse import urlparse
from validator_collection import checkers
from bs4 import BeautifulSoup
from huepy import bold, info, run, que, bad, good, red


requests.packages.urllib3.disable_warnings()


 # Checa se a url é valida.
def valid_url(url: str) -> bool:
    parsed_url = urlparse(url)
    if not (checkers.is_url(parsed_url.geturl()) or checkers.is_ip_address(parsed_url.geturl())):
        # Adiciona https caso estiver faltando.
        parsed_url = parsed_url._replace(**{"scheme": "https"})
        parsed_url = parsed_url._replace(**{"netloc": parsed_url[2]}) 
        parsed_url = parsed_url._replace(**{"path": ""})
        # Checa com a url já configurada.
        if not (checkers.is_url(parsed_url.geturl()) or checkers.is_ip_address(parsed_url.geturl())):
            return False
    return True

# Função para validar as configurações do Header
def validaHeader(nome_header, array_headers):
    if nome_header == 'Strict-Transport-Security':
        hsts = array_headers['Strict-Transport-Security']
        if 'max-age=31536000' in hsts:
            print(" ->",good('Strict-Transport-Security Presente.'))
        else:
            print(" ->",bad('Strict-Transport-Security Ausente'))

    # X-Frame-Options
    if nome_header == 'X-Frame-Options':
        xfo = array_headers['X-Frame-Options']
        if xfo == 'DENY' or xfo == 'SAMEORIGIN':
            print(" ->",good('X-Frame-Options Presente.'))
        else:
            print(" ->",bad('X-Frame-Options Ausente'))

    # X-XSS-Protection
    if nome_header == 'X-XSS-Protection':
        xss = array_headers['X-XSS-Protection']
        if xss == '1; mode=block' or xss == '1':
            print(" ->",good('X-XSS-Protection Presente.'))
        else:
            print(" ->",bad('X-XSS-Protection Ausente'))

    # X-Content-Type-Options
    if nome_header == 'X-Content-Type-Options':
        xcto = array_headers['X-Content-Type-Options']
        if xcto == 'nosniff':
            print(" ->",good('X-Content-Type-Options Presente.'))
        else:
            print(" ->",bad('X-Content-Type-Options Ausente'))

    # Referrer-Policy
    if nome_header == 'Referrer-Policy':
        rp = array_headers['Referrer-Policy']
        if rp == 'no-referrer' or rp == 'no-referrer-when-downgrade' or rp == 'same-origin' or rp == 'strict-origin' or rp == 'strict-origin-when-cross-origin' or rp == 'origin' or rp == 'origin-when-cross-origin' or rp == 'unsafe-url':
            print(" ->",good('Referrer-Policy Presente.'))
        else:
            print(" ->",bad('Referrer-Policy Ausente'))
    
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

    # Adiciona https caso não tenha.
    args.url = 'https://' + args.url if not args.url.startswith('https') else args.url
    if not valid_url(args.url):
        parser.print_help()
        exit()

    try:
        response = session.get(url=args.url)
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
        'Referrer-Policy'              
    ]

    cookie_checks = [
        'Expires',  
        'HttpOnly', 
        'Secure',
        'SameSite'
    ]

    # Verifica código HTTP da response
    print(run(f"{bold('URL testada')}: {args.url}"))
    if response.status_code == 200:
        print(good(f"{bold('Response status')}: {response.status_code}")) 
    elif response.status_code in [300,301,302] :
        print(info(f"{bold('Response status')}: {response.status_code}")) 
    else:
        print(bad(f"{bold('Response status')}: {response.status_code}")) 

    # Caso verbose seja true nas flags, mostra a request e response.
    if args.verbose:
        print(info(bold('Request headers:')))
        print(json.dumps(dict(session.headers), indent=2, sort_keys=True))

        print(info(bold('Response headers:')))
        print(json.dumps(dict(headers), indent=2, sort_keys=True))

    # Começa a checagem dos headers.
    print(f"\n{run(bold('Checando Headers ...'))}")
    
    for check_head in check_headers:
        if check_head.lower() in headers:
            print(good(f'{check_head} Presente.'))
            validaHeader(check_head, headers)
        else:
            print(bad(f'{check_head} Ausente.'))

    # Realiza a separação dos cookies.
    cookies = headers['Set-Cookie']
    pattern = r',(?!\s*\d)' # Regex para não separar quando encontrar uma virgula dentro do expires=...
    cookies_list = re.split(pattern, cookies)

    # Começa a checagem de cookies
    print(f"\n{run(bold('Checando cookies...'))}")
    for cookie in cookies_list:
        print(f"{info(bold('cookie: '))} {cookie}")
        for cookie_check in cookie_checks:
            if cookie_check.lower() in cookie.lower():
                print(" ->",good(f'{cookie_check} Presente.'))
            else:
                print(" ->",bad(f'{cookie_check} Ausente.'))

if __name__ == '__main__':
    main()
