#!/usr/bin/env python3
import socket
import dns.resolver
import requests
import whois
import ssl
import geoip2.database
from bs4 import BeautifulSoup
import re
import json
from pprint import pprint

def gather_network_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        dns_records = []
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'SPF']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for answer in answers:
                    dns_records.append((record_type, answer.to_text()))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass

        response = requests.get(f'http://{domain}')
        server_type = response.headers.get('Server')
        server_version = response.headers.get('Server-Version')
        operating_system = response.headers.get('X-Operating-System')

        return {
            'ip_address': ip_address,
            'dns_records': dns_records,
            'server_type': server_type,
            'server_version': server_version,
            'operating_system': operating_system
        }
    except Exception as e:
        return {'error': str(e)}

def gather_domain_registration_info(domain):
    try:
        whois_info = whois.whois(domain)
        return {
            'registrant_name': whois_info.name,
            'registrant_organization': whois_info.org,
            'registrant_email': whois_info.email,
            'registrant_phone_number': whois_info.phone,
            'registration_date': whois_info.creation_date.strftime('%Y-%m-%d %H:%M:%S') if whois_info.creation_date else None,
            'expiration_date': whois_info.expiration_date.strftime('%Y-%m-%d %H:%M:%S') if whois_info.expiration_date else None
        }
    except Exception as e:
        return {'error': str(e)}

def gather_ssl_tls_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()
                return {
                    'certificate_issuer': dict(x[0] for x in certificate.get('issuer')),
                    'certificate_subject': dict(x[0] for x in certificate.get('subject')),
                    'certificate_expiration_date': certificate.get('notAfter'),
                    'certificate_serial_number': certificate.get('serialNumber')
                }
    except Exception as e:
        return {'error': str(e)}

def gather_http_header_info(domain):
    try:
        response = requests.get(f'http://{domain}')
        return {
            'server_headers': response.headers.get('Server'),
            'content_type': response.headers.get('Content-Type'),
            'content_length': response.headers.get('Content-Length'),
            'set_cookie_headers': response.headers.get('Set-Cookie'),
            'cache_control_headers': response.headers.get('Cache-Control')
        }
    except Exception as e:
        return {'error': str(e)}

def gather_geolocation_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        reader = geoip2.database.Reader('/home/kali/Desktop/infoinspector/GeoLite2-City_20240709/GeoLite2-City.mmdb')
        response = reader.city(ip_address)
        return {
            'country': response.country.name,
            'region': response.subdivisions.most_specific.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except Exception as e:
        return {'error': str(e)}

def gather_email_addresses(domain):
    email_addresses = []
    try:
        for protocol in ['http', 'https']:
            try:
                response = requests.get(f'{protocol}://{domain}', headers={'User-Agent': 'Mozilla/5.0'})
                soup = BeautifulSoup(response.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    if a['href'].startswith('mailto:'):
                        email_addresses.append(a['href'].replace('mailto:', ''))
                email_addresses.extend(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text))
                break  # If successful, break the loop
            except requests.RequestException:
                continue
    except Exception as e:
        return {'error': str(e)}

    return {'email_addresses': list(set(email_addresses))}


def main():
    print("****************************************************")
    print("*                   INFOINSPECTOR                  *")
    print("****************************************************")
    print("\nThis tool will gather the following information about the domain you enter:")
    print("1. Network Information")
    print("2. Domain Registration Information")
    print("3. SSL/TLS Certificate Information")
    print("4. Email Addresses ")
    print("5. Geolocation Information")
    print("6. HTTP Header Information")
  
    print("\nNote: Enter domain name only, not complete URL")
    
    domain = input('\nEnter a domain: ')
    
    network_info = gather_network_info(domain)
    domain_registration_info = gather_domain_registration_info(domain)
    ssl_tls_certificate_info = gather_ssl_tls_certificate_info(domain)
    geolocation_info = gather_geolocation_info(domain)
    email_addresses = gather_email_addresses(domain)
    http_header_info = gather_http_header_info(domain)
 

    print('\nNetwork Information:')
    pprint(network_info)

    print('\nDomain Registration Information:')
    pprint(domain_registration_info)

    print('\nSSL/TLS Certificate Information:')
    pprint(ssl_tls_certificate_info)

    print('\nGeolocation Information:')
    pprint(geolocation_info)

    print('\nEmail Addresses:')
    pprint(email_addresses)
    
    print('\nHTTP Header Information:')
    pprint(http_header_info)


if __name__ == '__main__':
    main()
