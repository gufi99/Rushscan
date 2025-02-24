import requests
import re
import ssl
import socket
from urllib.parse import urlparse

user_url = str(input('[+] Enter Target URL to scan: '))

potential_xss = []
missing_headers = []
sql_injection_vulnerabilities = []
ssl_tls_info = []

def check_security_headers(response):
    headers = response.headers
    if 'Content-Security-Policy' not in headers:
        missing_headers.append('Content-Security-Policy')
    if 'X-Frame-Options' not in headers:
        missing_headers.append('X-Frame-Options')
    if 'X-XSS-Protection' not in headers:
        missing_headers.append('X-XSS-Protection')
    if 'Strict-Transport-Security' not in headers:
        missing_headers.append('Strict-Transport-Security')
    if 'X-Content-Type-Options' not in headers:
        missing_headers.append('X-Content-Type-Options')
    if 'Referrer-Policy' not in headers:
        missing_headers.append('Referrer-Policy')

def check_xss_vulnerabilities(response_text, url):
    xss_patterns = [
        r'<script.*?>.*?</script>',  # Script tags
        r'on\w+=".*?"',              # Inline event handlers
        r'<img.*?src=.*?onerror=.*?>',  # Image onerror
        r'<svg.*?onload=.*?>',      # SVG onload
        r'javascript:.*?;',          # JavaScript URLs
    ]
    
    for pattern in xss_patterns:
        for match in re.finditer(pattern, response_text, re.I):
            start, end = match.span()
            potential_xss.append(f'Potential XSS found in {url}: Pattern matched - {pattern} at position {start}-{end}')

    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    for payload in payloads:
        if payload in response_text:
            start = response_text.index(payload)
            end = start + len(payload)
            potential_xss.append(f'Potential XSS found in {url}: Payload reflected - {payload} at position {start}-{end}')

def check_sql_injection(url):
    # Common SQL injection payloads
    sql_payloads = ["' OR '1'='1", '" OR "1"="1', "'; DROP TABLE users; --"]
    for payload in sql_payloads:
        test_url = f"{url}?param={payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
            sql_injection_vulnerabilities.append(f'Potential SQL Injection found with payload: {payload} at URL: {test_url}')

def check_ssl_tls(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port if parsed_url.port else 443  # Default to 443 for HTTPS

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info = ssock.version()
                cipher = ssock.cipher()
                ssl_tls_info.append(f'SSL/TLS version: {ssl_info}, Cipher: {cipher}')
                # Check for old SSL/TLS versions
                if "SSLv3" in ssl_info or "TLSv1" in ssl_info or "TLSv1.1" in ssl_info:
                    ssl_tls_info.append(f'Warning: Old SSL/TLS version detected: {ssl_info}')
    except Exception as e:
        ssl_tls_info.append(f'Error checking SSL/TLS: {e}')

try:
    # Make a request to the target URL
    response = requests.get(user_url)
    check_security_headers(response)
    check_xss_vulnerabilities(response.text, user_url)
    check_sql_injection(user_url)
    check_ssl_tls(user_url)

except requests.exceptions.MissingSchema:
    print("Invalid URL format.")
except requests.exceptions.ConnectionError:
    print("Connection error. Please check the URL.")

# Print results
print("\n[+] Potential XSS vulnerabilities:")
for xss in potential_xss:
    print(xss)

print("\n[+] Missing Security Headers:")
for header in missing_headers:
    print(header)

print("\n[+] Potential SQL Injection vulnerabilities:")
for sql in sql_injection_vulnerabilities:
    print(sql)

print("\n[+] SSL/TLS Information:")
for ssl_info in ssl_tls_info:
    print(ssl_info)
