from urllib.parse import urlparse

import idna
import socket
import requests

from OpenSSL import SSL
from cryptography.x509.oid import NameOID
from tldextract import extract


class HostCertificate:
    def __init__(self, url_draw, port_number=443):
        self.__port_number = port_number
        self.__is_defined_certificate_information = False
        self.__errors = []
        self.__start_url__(url_draw)

    def collect_certificate_information(self):
        hostname_idna = idna.encode(self.__url_hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.__url_hostname, self.__port_number))
        peer_name = sock.getpeername()[0]
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()
        self.__define_certificate_information__(crypto_cert, peer_name, sock_ssl, cert)
        self.__is_valid_common_name__()
        self.__verify_forced_redirect()
        self.__is_valid_certificate__()

    def get_host_certificate_information(self):
        if self.__is_defined_certificate_information:
            return {
                'host_ip_address': self.__host_ip_address,
                'protocol_version_name': self.__protocol_version_name,
                'forced_redirect_to_https': self.__forced_redirect_to_https,
                'https_redirect_to_same_domain': self.__https_redirect_to_same_domain,
                'certificate_valid': self.__is_valid_certificate,
                'certificate_version': self.__certificate_version,
                'issuer': self.__issuer,
                'subject': self.__subject,
                'algorithm_name': self.__algorithm_name,
                'key_size': self.__key_size,
                'certificate_has_expired': self.__certificate_has_expired,
                'start_certificate_validate': self.__start_certificate_validate,
                'certificate_expiration': self.__certificate_expiration,
                'errors': self.__errors
            }
        else:
            raise Exception('first you need to call collect_certificate_information() method')

    def __verify_forced_redirect(self):
        if self.__url_hostname is not None:
            request = requests.get(f"http://{self.__url_hostname}", allow_redirects=False, verify=False)
            if 300 <= request.status_code <= 308 and urlparse(request.headers['location']).scheme == 'https':
                tsd_location, td_location, tsu_location = extract(request.headers['location'])
                tsd_origin, td_origin, tsu_origin = extract(self.__url_hostname)
                redirect_domain = f"{td_location}.{tsu_location}"
                origin_domain = f"{td_origin}.{tsu_origin}"
                if redirect_domain == origin_domain:
                    self.__https_redirect_to_same_domain = True
                else:
                    self.__https_redirect_to_same_domain = False
                self.__forced_redirect_to_https = True
            else:
                self.__forced_redirect_to_https = False
                self.__https_redirect_to_same_domain = False

    def __start_url__(self, url_draw):
        self.__url_parse = urlparse(url_draw)
        self.__url_scheme = self.__url_parse.scheme
        self.__url_netloc = self.__url_parse.netloc
        self.__url_hostname = self.__url_parse.hostname
        self.__url_path = self.__url_parse.path
        self.__url_params = self.__url_parse.params
        self.__url_query = self.__url_parse.query
        self.__url_fragment = self.__url_parse.fragment
        if self.__url_hostname is None:
            self.__url_hostname = self.__url_path

    def __define_certificate_information__(self, crypto_cert, peer_name, sock_ssl, cert):
        self.__protocol_version_name = sock_ssl.get_protocol_version_name()
        self.__host_ip_address = peer_name
        self.__certificate_version = crypto_cert.version.name
        try:
            self.__issuer = crypto_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            self.__issuer = None
            self.__errors.append('no_issuer')
        try:
            self.__subject = crypto_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            self.__error_no_subject = False
        except Exception:
            self.__subject = None
            self.__errors.append('no_subject')
        self.__algorithm_name = crypto_cert.signature_hash_algorithm.name
        self.__key_size = crypto_cert.public_key().key_size
        self.__certificate_expiration = crypto_cert.not_valid_after
        self.__start_certificate_validate = crypto_cert.not_valid_before
        self.__is_defined_certificate_information = True
        if cert.has_expired():
            self.__errors.append('certificate_has_expired')
        self.__certificate_has_expired = cert.has_expired()

    def __verify_common_name__(self):
        if self.__subject is not None:
            hostname = self.__url_hostname.replace("www.", "")
            subject = self.__subject.replace("www.", "")
            if ("*." in subject and subject.count("*") == 1 and
                    subject.count(".") > 1 and "." in hostname):
                left_expected, right_expected = subject.split("*.")
                left_hostname, right_hostname = hostname.split(".", 1)
                if (left_hostname.startswith(left_expected) and
                        right_expected == right_hostname):
                    return True
                if subject.replace("*.", "") == hostname:
                    return True
            elif subject == hostname:
                return True
            else:
                return False
        else:
            return False

    def __is_valid_common_name__(self):
        if not self.__verify_common_name__():
            self.__errors.append('common_name_invalid')

    def __is_valid_certificate__(self):
        if len(self.__errors) != 0:
            self.__is_valid_certificate = False
        else:
            self.__is_valid_certificate = True
