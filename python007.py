import dns.resolver
import requests
import subprocess
import ssl
import socket
from ipwhois import IPWhois
import shodan

# Shodan API Key (replace with your API key)
SHODAN_API_KEY = "uZExm6lFJWM4dqBKzXC9HVMfkciIxCir"

# Function to perform DNS lookup (A, CNAME, MX, NS, SOA records)
def get_dns_records(domain):
    result = {}
    dns_records = ['A', 'CNAME', 'MX', 'NS', 'SOA']
    for record in dns_records:
        try:
            result[record] = [str(data) for data in dns.resolver.resolve(domain, record)]
        except Exception as e:
            result[record] = f"Error: {e}"
    return result

# Function for Reverse IP lookup
def reverse_ip_lookup(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if response.status_code == 200:
            return response.text.splitlines()
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

# Function for Traceroute
def traceroute(domain):
    try:
        process = subprocess.Popen(["traceroute", domain], stdout=subprocess.PIPE)
        output = [line.decode().strip() for line in process.stdout]
        return output
    except Exception as e:
        return f"Error: {e}"

# Function to get SSL/TLS certificate information
def get_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return cert
    except Exception as e:
        return f"Error: {e}"

# Function for ASN Lookup
def get_asn_info(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return {
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "network_name": result.get("network", {}).get("name"),
            "network_country": result.get("network", {}).get("country")
        }
    except Exception as e:
        return f"Error: {e}"

# Function to get host info from Shodan
def get_shodan_info(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return {
            "ip": host["ip_str"],
            "organization": host.get("org", "n/a"),
            "os": host.get("os", "n/a"),
            "open_ports": host.get("ports", [])
        }
    except shodan.APIError as e:
        return f"Error: {e}"

# Function to classify the domain as suspicious or safe
def classify_safety(results):
    suggestions = []

    # SSL/TLS Certificate Check
    cert = results.get('ssl_certificate', {})
    if isinstance(cert, dict) and 'notAfter' in cert:
        suggestions.append("SSL/TLS Certificate is valid.")
    else:
        suggestions.append("SSL/TLS Certificate is missing or invalid. Suspicious.")

    # Check open ports from Shodan results
    shodan_info = results.get('shodan_info', {})
    if isinstance(shodan_info, dict) and shodan_info.get('open_ports'):
        suspicious_ports = [8080, 3389, 23, 21]
        for port in shodan_info['open_ports']:
            if port in suspicious_ports:
                suggestions.append(f"Open port {port} is suspicious.")
            else:
                suggestions.append(f"Port {port} appears safe.")

    # Check ASN for suspicious hosting providers
    asn_info = results.get('asn_info', {})
    if 'CLOUDFLARENET' in asn_info.get('asn_description', ''):
        suggestions.append("Domain is using Cloudflare. Verify if it is hiding real hosting details.")
    elif 'asn_description' in asn_info:
        suggestions.append(f"Hosting provider is {asn_info['asn_description']}, which seems legitimate.")

    # DNS Record Check
    if 'dns_records' in results:
        a_record = results['dns_records'].get('A', [])
        if not a_record:
            suggestions.append("No A record found, could be suspicious.")
        else:
            suggestions.append("A record found, the domain resolves correctly.")

    return suggestions

# Main function to integrate all the tools and provide output
def analyze_website(domain):
    results = {}

    # Step 1: DNS Records
    results['dns_records'] = get_dns_records(domain)

    # Step 2: Get IP from A record for further analysis
    try:
        ip = dns.resolver.resolve(domain, 'A')[0].to_text()
    except Exception as e:
        return {"error": f"Unable to resolve IP from domain: {e}"}

    # Step 3: Reverse IP Lookup
    results['reverse_ip_lookup'] = reverse_ip_lookup(ip)

    # Step 4: Traceroute
    results['traceroute'] = traceroute(domain)

    # Step 5: SSL Certificate Info
    results['ssl_certificate'] = get_ssl_cert(domain)

    # Step 6: ASN Information
    results['asn_info'] = get_asn_info(ip)

    # Step 7: Shodan Info
    results['shodan_info'] = get_shodan_info(ip)

    # Step 8: Classify website safety
    results['safety_suggestions'] = classify_safety(results)

    return results

# Example usage
if __name__ == "__main__":
    # Dynamically ask for domain input
    domain = input("Enter the domain name you want to analyze: ")
    report = analyze_website(domain)

    # Print the result in a readable format
    for key, value in report.items():
        print(f"\n--- {key.upper()} ---")
        if isinstance(value, list):
            for item in value:
                print(item)
        else:
            print(value)

