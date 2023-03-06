# Simple Security Headers

A tool for checking HTTP headers and cookies attributes.

## Security HTTP headers checked
- Content-Security-Policy (CSP)
- Feature-Policy
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- [TO DO...]

## Cookie attributes checked
- Expires
- HttpOnly
- Secure
- Path=/

## Install

```txt
git clone https://github.com/pedpedro/Security-Headers-Checker.git
cd Security-Headers-Checker
pip install -r requirements.txt
```

## Usage

```txt
usage: simple-security-headers.py [-h] -u URL [--verbose]
```

## Output 

[TO DO...]


This tool was fork from martibarri (https://github.com/martibarri/simple-security-headers) which is inspired by [CrossHead](https://github.com/alvarodh5/CrossHead) project from alvarodh5 and Cristian Barrientos. I did some modifications for my use cases.
