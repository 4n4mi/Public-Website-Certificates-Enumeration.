import ssl
import socket
import datetime
import pandas as pd
import cryptography.x509
import cryptography.hazmat.backends

# Read domains from domains.txt
with open("domains.txt", "r") as file:
    domains = file.read().splitlines()

# List of weak hashing algorithms to check against
WEAK_HASH_ALGORITHMS = ["MD5", "SHA1"]

def get_certificate(hostname):
    try:
        pem_cert = ssl.get_server_certificate((hostname, 443))
        cert = cryptography.x509.load_pem_x509_certificate(pem_cert.encode(), cryptography.hazmat.backends.default_backend())
        return cert, None
    except Exception as e:
        return None, str(e)

def extract_certificate_details(cert):
    if not cert:
        return [None] * 10
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    issued_to = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
    issued_by = cert.issuer.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
    valid_from = cert.not_valid_before.replace(tzinfo=None)
    expiry_date = cert.not_valid_after_utc.replace(tzinfo=None)
    self_signed = cert.issuer == cert.subject
    ca_name = cert.issuer.get_attributes_for_oid(cryptography.x509.oid.NameOID.ORGANIZATION_NAME)[0].value if not self_signed else ''
    signature_algorithm = cert.signature_algorithm_oid._name
    weak_hash_used = any(algorithm in signature_algorithm for algorithm in WEAK_HASH_ALGORITHMS)
    wildcard = '*' in issued_to
    current_time = datetime.datetime.now()
    days_until_expiry = (expiry_date - current_time).days
    return issued_to, issued_by, valid_from, expiry_date, self_signed, ca_name, signature_algorithm, weak_hash_used, wildcard, days_until_expiry

def mark_expired_and_self_signed(row):
    style = [''] * len(row)
    if row['Self Signed']:
        style = ['background-color: red; border: 1px solid black;'] * len(row)
    elif row['Expiry Date'] < datetime.datetime.now():
        style = ['background-color: red; border: 1px solid black;'] * len(row)
    elif row['Expiry Date'] < datetime.datetime.now() + datetime.timedelta(days=30):
        style = ['background-color: yellow; border: 1px solid black;'] * len(row)
    for i in range(len(style)):
        style[i] += 'border: 1px solid black;'
    return style

def main():
    connectable_domains = []
    not_connectable_domains = []
    all_details = []
    for domain in domains:
        cert, error = get_certificate(domain)
        if cert:
            details = [domain] + list(extract_certificate_details(cert))
            all_details.append(details)
            connectable_domains.append(domain)
        else:
            not_connectable_domains.append((domain, error))
            print(f"Error connecting to {domain}: {error}")
    if all_details or not_connectable_domains:
        df = pd.DataFrame(all_details, columns=['Domain', 'Issued To', 'Issued By', 'Valid From', 'Expiry Date', 'Self Signed', 'CA Name', 'Certificate Signature Algorithm', 'Weak Hash Used', 'Wildcard', 'Days Until Expiry'])
        styled_df = df.style.apply(mark_expired_and_self_signed, axis=1)
        
        # Include SSL handshake failures in the DataFrame
        error_df = pd.DataFrame(not_connectable_domains, columns=['Domain', 'Error'])
        df = pd.concat([df, error_df], ignore_index=True)
        
        # Save DataFrame to Excel
        filename = f'certificate_details_{datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.xlsx'
        
        # Move not connectable domains to the bottom
        df = df.sort_values(by='Error', na_position='last')
        
        styled_df = df.style.apply(mark_expired_and_self_signed, axis=1)
        styled_df.to_excel(filename, index=False)
        
        print(f"Certificate details saved to {filename}")
    else:
        print("No certificate details retrieved.")

if __name__ == "__main__":
    main()
