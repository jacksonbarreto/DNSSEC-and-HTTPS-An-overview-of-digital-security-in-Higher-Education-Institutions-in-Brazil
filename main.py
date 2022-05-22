from dnssec.DNSSecValidator import DNSSecValidator
from httpsec.HTTPSInspector import HTTPSInspector
import pandas as pd

if __name__ == '__main__':

    ies = pd.read_csv('./ies_with_url_ultra_little.csv', encoding='latin')
    ies['nameserver'] = 'a'
    ies['has_dnssec'] = 'a'
    ies['dnssec_is_valid'] = 'a'
    ies['algorithm_name'] = 'a'
    ies['has_https'] = 'a'

    ies['forced_redirect_to_https'] = 'a'
    ies['https_redirect_to_same_domain'] = 'a'
    ies['https_protocol_version_name'] = 'a'
    ies['https_certificate_valid'] = 'a'
    ies['https_certificate_version'] = 'a'
    ies['issuer'] = 'a'
    ies['subject'] = 'a'
    ies['https_algorithm_name'] = 'a'
    ies['https_key_size'] = 'a'
    ies['https_start_certificate_validate'] = 'a'
    ies['https_certificate_expiration'] = 'a'

    dnssec_results = []
    nameserver = []
    has_dnssec = []
    dnssec_is_valid = []
    dnssec_algorithm_name = []

    forced_redirect_to_https = []
    https_redirect_to_same_domain = []
    https_protocol_version_name = []
    certificate_valid = []
    certificate_version = []
    issuer = []
    subject = []
    https_algorithm_name = []
    https_key_size = []
    https_start_certificate_validate = []
    https_certificate_expiration = []
    has_https = []

    for row in ies.itertuples():
        print("analyzing record ", getattr(row, 'Index'), "/", len(ies))
        if len(str(row.url)) > 3:
            dns_sec = DNSSecValidator(row.url)
            dns_sec.validator()
            dns_sec_info = dns_sec.get_information()
            row_nameserver = dns_sec_info['nameserver']
            row_has_dnssec = dns_sec_info['has_dnssec']
            row_dnssec_is_valid = dns_sec_info['dnssec_is_valid']
            row_algorithm_name = dns_sec_info['algorithm_name']

            hostCertificate = HTTPSInspector(row.url)
            hostCertificate.inspect()
            host_info = hostCertificate.get_host_certificate_information()

            row_has_https = host_info['has_https']
            row_forced_redirect_to_https = host_info['forced_redirect_to_https']
            row_https_redirect_to_same_domain = host_info['https_redirect_to_same_domain']
            row_https_protocol_version_name = host_info['protocol_version_name']
            row_certificate_valid = host_info['certificate_valid']
            row_certificate_version = host_info['certificate_version']
            row_issuer = host_info['issuer']
            row_subject = host_info['subject']
            row_https_algorithm_name = host_info['algorithm_name']
            row_https_key_size = host_info['key_size']
            row_https_start_certificate_validate = host_info['start_certificate_validate']
            row_https_certificate_expiration = host_info['certificate_expiration']

        else:
            row_nameserver = ""
            row_has_dnssec = ""
            row_dnssec_is_valid = ""
            row_algorithm_name = ""

            row_has_https = ""
            row_forced_redirect_to_https = ""
            row_https_redirect_to_same_domain = ""
            row_https_protocol_version_name = ""
            row_certificate_valid = ""
            row_certificate_version = ""
            row_issuer = ""
            row_subject = ""
            row_https_algorithm_name = ""
            row_https_key_size = ""
            row_https_start_certificate_validate = ""
            row_https_certificate_expiration = ""

        nameserver.append(row_nameserver)
        has_dnssec.append(row_has_dnssec)
        dnssec_is_valid.append(row_dnssec_is_valid)
        dnssec_algorithm_name.append(row_algorithm_name)

        forced_redirect_to_https.append(row_forced_redirect_to_https)
        https_redirect_to_same_domain.append(row_https_redirect_to_same_domain)
        https_protocol_version_name.append(row_https_protocol_version_name)
        certificate_valid.append(row_certificate_valid)
        certificate_version.append(row_certificate_version)
        issuer.append(row_issuer)
        subject.append(row_subject)
        https_algorithm_name.append(row_https_algorithm_name)
        https_key_size.append(row_https_key_size)
        https_start_certificate_validate.append(row_https_start_certificate_validate)
        https_certificate_expiration.append(row_https_certificate_expiration)
        has_https.append(row_has_https)

    ies['nameserver'] = nameserver
    ies['has_dnssec'] = has_dnssec
    ies['dnssec_is_valid'] = dnssec_is_valid
    ies['algorithm_name'] = dnssec_algorithm_name
    ies['forced_redirect_to_https'] = forced_redirect_to_https
    ies['https_redirect_to_same_domain'] = https_redirect_to_same_domain
    ies['https_protocol_version_name'] = https_protocol_version_name
    ies['https_certificate_valid'] = certificate_valid
    ies['https_certificate_version'] = certificate_version
    ies['issuer'] = issuer
    ies['subject'] = subject
    ies['https_algorithm_name'] = https_algorithm_name
    ies['https_key_size'] = https_key_size
    ies['https_start_certificate_validate'] = https_start_certificate_validate
    ies['https_certificate_expiration'] = https_certificate_expiration
    ies['has_https'] = has_https

    ies.to_csv('ies_with_sec_info.csv', encoding='utf-8', index=False)
