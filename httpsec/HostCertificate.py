from urllib.parse import urlparse

import idna
import socket
import requests

from OpenSSL import SSL
from cryptography.x509.oid import NameOID
from tldextract import extract


class HostCertificate:
    def __init__(self, host):
        self.__host_ip_address = None
        self.__sock_ssl = None
        self.__sock_ssl = None
        self.__certificate = None
        self.__crypto_certificate = None
        self.__forced_redirect_to_https = False
        self.__https_redirect_to_same_domain = False
        self.__errors = []
        self.__normalize_domain__(host)

    def collect_certificate_information(self):
        self.__connect_to_socket__()
        self.__get_certificate__()
        self.__close_socket_connection__()
        self.__define_certificate_information__()
        self.__verify_errors_in_certificate__()
        self.__verify_forced_redirect()
        self.__is_valid_certificate__()

    def get_host_certificate_information(self):
        if self.__crypto_certificate is not None:
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
                self.__forced_redirect_to_https = True
                _, td_location, tsu_location = extract(request.headers['location'])
                _, td_origin, tsu_origin = extract(str(self.__url_hostname))
                redirect_domain = f"{td_location}.{tsu_location}"
                origin_domain = f"{td_origin}.{tsu_origin}"
                if redirect_domain == origin_domain:
                    self.__https_redirect_to_same_domain = True
                else:
                    self.__https_redirect_to_same_domain = False
        else:
            raise Exception('the hostname is null')

    def __normalize_domain__(self, url_draw):
        if urlparse(url_draw).hostname is not None:
            self.__url_hostname = urlparse(url_draw).hostname
        else:
            self.__url_hostname = urlparse(url_draw).path

    def __define_certificate_information__(self):
        if self.__crypto_certificate is not None:
            self.__protocol_version_name = self.__sock_ssl.get_protocol_version_name()
            self.__certificate_version = self.__crypto_certificate.version.name
            self.__get_issuer__()
            self.__get_subject__()
            self.__algorithm_name = self.__crypto_certificate.signature_hash_algorithm.name
            self.__key_size = self.__crypto_certificate.public_key().key_size
            self.__certificate_expiration = self.__crypto_certificate.not_valid_after
            self.__start_certificate_validate = self.__crypto_certificate.not_valid_before
            if self.__certificate.has_expired():
                self.__errors.append('certificate_has_expired')
        else:
            raise Exception('the crypto certificate is null')

    def __get_issuer__(self):
        if self.__crypto_certificate is not None:
            try:
                self.__issuer = self.__crypto_certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                self.__issuer = None
                self.__errors.append('no_issuer')
        else:
            raise Exception('the crypto certificate is null')

    def __get_subject__(self):
        if self.__crypto_certificate is not None:
            try:
                self.__subject = self.__crypto_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                self.__error_no_subject = False
            except Exception:
                self.__subject = None
                self.__errors.append('no_subject')
        else:
            raise Exception('the crypto certificate is null')

    def __verify_errors_in_certificate__(self):
        self.__is_valid_common_name__()

    def __verify_common_name__(self):
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

    def __is_valid_common_name__(self):
        if self.__subject is not None:
            if not self.__verify_common_name__():
                self.__errors.append('common_name_invalid')

    def __is_valid_certificate__(self):
        if len(self.__errors) != 0:
            self.__is_valid_certificate = False
        else:
            self.__is_valid_certificate = True

    def __get_certificate__(self):
        if self.__sock_ssl is not None:
            self.__certificate = self.__sock_ssl.get_peer_certificate()
            self.__crypto_certificate = self.__certificate.to_cryptography()
        else:
            raise Exception("don't exist a connection")

    def __connect_to_socket__(self):
        if self.__url_hostname is not None:
            self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__sock.connect((self.__url_hostname, 443))
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.check_hostname = False
            self.__host_ip_address = self.__sock.getpeername()
            ctx.verify_mode = SSL.VERIFY_NONE
            self.__sock_ssl = SSL.Connection(ctx, self.__sock)
            self.__sock_ssl.set_connect_state()
            self.__sock_ssl.set_tlsext_host_name(idna.encode(self.__url_hostname))
            self.__sock_ssl.do_handshake()
        else:
            raise Exception("unable to establish a connection because the hostname is null")

    def __close_socket_connection__(self):
        if self.__sock_ssl is not None:
            self.__sock_ssl.close()
            self.__sock.close()
        else:
            raise Exception("don't exist a connection")
