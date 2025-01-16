"""
DNS Lookup Tool

This script performs a DNS lookup for a given domain name and retrieves various DNS records,
including A records (IPv4 addresses), AAAA records (IPv6 addresses), MX records (mail servers),
NS records (name servers), and TXT records. The output includes both the record details and the TTL (Time To Live).

Dependencies:
    dnspython - To install, run: pip install dnspython

Usage:
    Run the script and input the domain name when prompted.
"""

import dns.resolver

def dns_lookup(domain):
    """
    Performs DNS lookups for various record types for the given domain.

    Args:
        domain (str): The domain name to query.

    The function prints out:
        - A Records (IPv4 addresses) and their TTL
        - AAAA Records (IPv6 addresses) and their TTL
        - MX Records (Mail servers) with their preference and exchange server and their TTL
        - NS Records (Name servers) and their TTL
        - TXT Records and their TTL
    """

    print(f"\nDNS Lookup Results for: {domain}\n{'-'*50}")

    # Lookup A Records (IPv4 addresses)
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        print("\nA Records (IPv4 addresses):")
        for rdata in a_records:
            print(f"  {rdata.to_text()}")
        # Print TTL for A records
        print(f"TTL for A records: {a_records.rrset.ttl}")
    except Exception as e:
        print(f"Error retrieving A records: {e}")

    # Lookup AAAA Records (IPv6 addresses)
    try:
        aaaa_records = dns.resolver.resolve(domain, 'AAAA')
        print("\nAAAA Records (IPv6 addresses):")
        for rdata in aaaa_records:
            print(f"  {rdata.to_text()}")
        print(f"TTL for AAAA records: {aaaa_records.rrset.ttl}")
    except Exception as e:
        print(f"Error retrieving AAAA records: {e}")

    # Lookup MX Records (Mail servers)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        print("\nMX Records (Mail servers):")
        for rdata in mx_records:
            # Each MX record has a preference and an exchange (mail server)
            print(f"  Preference: {rdata.preference}, Exchange: {rdata.exchange.to_text()}")
        print(f"TTL for MX records: {mx_records.rrset.ttl}")
    except Exception as e:
        print(f"Error retrieving MX records: {e}")

    # Lookup NS Records (Name servers)
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        print("\nNS Records (Name servers):")
        for rdata in ns_records:
            print(f"  {rdata.to_text()}")
        print(f"TTL for NS records: {ns_records.rrset.ttl}")
    except Exception as e:
        print(f"Error retrieving NS records: {e}")

    # Lookup TXT Records
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        print("\nTXT Records:")
        for rdata in txt_records:
            # TXT records might contain multiple strings, so we join them if necessary.
            txt_string = " ".join(rdata.strings.decode('utf-8') if isinstance(rdata.strings, bytes) else s.decode('utf-8') for s in rdata.strings)
            print(f"  {txt_string}")
        print(f"TTL for TXT records: {txt_records.rrset.ttl}")
    except Exception as e:
        print(f"Error retrieving TXT records: {e}")

if __name__ == '__main__':
    # Prompt the user for the domain name to lookup
    domain_input = input("Enter the domain name for DNS lookup: ").strip()
    if domain_input:
        dns_lookup(domain_input)
    else:
        print("No domain name entered. Exiting.")