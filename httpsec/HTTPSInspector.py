from urllib.parse import urlparse

import idna
import socket
import requests
import urllib3

from OpenSSL import SSL
from cryptography.x509.oid import NameOID
from tldextract import extract
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import x25519


class HTTPSInspector:

    def __init__(self, host):
        self.__host_ip_address = None
        self.__sock_ssl = None
        self.__certificate = None
        self.__crypto_certificate = None
        self.__forced_redirect_to_https = False
        self.__https_redirect_to_same_domain = False
        self.__protocol_version_name = None
        self.__certificate_version = None
        self.__algorithm_name = None
        self.__issuer = None
        self.__subject = None
        self.__is_valid_certificate = False
        self.__start_certificate_validate = None
        self.__certificate_expiration = None
        self.__key_size = None
        self.__has_https = False
        self.__x_xss = None
        self.__x_content = None
        self.__x_frame = None
        self.__public_key_type = None
        self.__errors = []
        self.__normalize_domain__(host)
        self.__location = None

    def inspect(self):
        urllib3.disable_warnings()
        try:
            if self.__has_https__():
                self.__has_https = True
                if self.__has_forced_redirect_from_http_to_https__():
                    self.__forced_redirect_to_https = True
                    if self.__is_forced_redirect_to_same_domain__(self.__location):
                        self.__https_redirect_to_same_domain = True
                    else:
                        self.__https_redirect_to_same_domain = False
                else:
                    self.__forced_redirect_to_https = False

                self.__check_security_headers__()
                self.__define_certificate_information__()
                self.__verify_errors_in_certificate__()
            else:
                self.__has_https = False
        except Exception as e:
            self.__errors.append(str(e))

    def get_host_certificate_information(self):
        return {
            'has_https': self.__has_https,
            'host_ip_address': self.__host_ip_address,
            'protocol_version_name': self.__protocol_version_name,
            'forced_redirect_to_https': self.__forced_redirect_to_https,
            'https_redirect_to_same_domain': self.__https_redirect_to_same_domain,
            'X-Frame-Options': self.__x_frame ,
            'X-Content-Type-Options': self.__x_content,
            'X-XSS-Protection': self.__x_xss,
            'certificate_valid': self.__is_valid_certificate,
            'certificate_version': self.__certificate_version,
            'issuer': self.__issuer,
            'subject': self.__subject,
            'algorithm_name': self.__algorithm_name,
            'key_size':  self.__get_key_size__(),
            'public_key_type': self.__public_key_type,
            'start_certificate_validate': self.__start_certificate_validate,
            'certificate_expiration': self.__certificate_expiration,
            'errors': self.__errors
        }

    def __get_key_size__(self):
        if self.__key_size is None:
            return 0
        else:
            return self.__key_size

    def __check_pubkey_type(self):
        public_key = self.__crypto_certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            self.__public_key_type = rsa.RSAPublicKey.__name__
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            self.__public_key_type = ec.EllipticCurvePublicKey.__name__
        elif isinstance(public_key, dsa.DSAPublicKey):
            self.__public_key_type = dsa.DSAPublicKey.__name__
        elif isinstance(public_key, ed448.Ed448PublicKey):
            self.__public_key_type = ed448.Ed448PublicKey.__name__
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            self.__public_key_type = ed25519.Ed25519PublicKey.__name__
        elif isinstance(public_key, x448.X448PublicKey):
            self.__public_key_type = x448.X448PublicKey.__name__
        elif isinstance(public_key, x25519.X25519PublicKey):
            self.__public_key_type = x25519.X25519PublicKey.__name__
        else:
            self.__public_key_type = "undefined"

    def __check_security_headers__(self):
        if self.__url_hostname is not None:
            response = requests.head(f"https://{self.__url_hostname}", allow_redirects=False, verify=False)
            headers = response.headers
            try:
                self.__x_frame = headers['X-Frame-Options']
            except:
                self.__x_frame = ""

            try:
                self.__x_content = headers['X-Content-Type-Options']
            except:
                self.__x_content = ""

            try:
                self.__x_xss = headers['X-XSS-Protection']
            except:
                self.__x_xss = ""
        else:
            raise Exception('HTTPSInspectorError(__check_security_headers__): the hostname is null')

    def __has_forced_redirect_from_http_to_https__(self):
        if self.__url_hostname is not None:
            response = requests.head(f"http://{self.__url_hostname}", allow_redirects=False, verify=False)
            if 300 <= response.status_code <= 308 and urlparse(response.headers['location']).scheme == 'https':
                self.__location = response.headers['location']
                return True
            else:
                return False
        else:
            raise Exception('HTTPSInspectorError(__has_forced_redirect_from_http_to_https__): the hostname is null')

    def __is_forced_redirect_to_same_domain__(self, location):
        if self.__location is not None:
            _, td_location, tsu_location = extract(location)
            _, td_origin, tsu_origin = extract(str(self.__url_hostname))
            redirect_domain = f"{td_location}.{tsu_location}"
            origin_domain = f"{td_origin}.{tsu_origin}"
            if redirect_domain == origin_domain:
                return True
            else:
                return False
        else:
            raise Exception('HTTPSInspectorError(__is_forced_redirect_to_same_domain__): the location is null')

    def __normalize_domain__(self, url_draw):
        if urlparse(url_draw).hostname is not None:
            self.__url_hostname = urlparse(url_draw).hostname
        else:
            self.__url_hostname = urlparse(url_draw).path

    def __define_certificate_information__(self):
        self.__get_certificate__()
        if self.__crypto_certificate is not None:
            self.__protocol_version_name = self.__sock_ssl.get_protocol_version_name()
            self.__certificate_version = self.__crypto_certificate.version.name
            self.__get_issuer__()
            self.__get_subject__()
            self.__algorithm_name = self.__crypto_certificate.signature_hash_algorithm.name
            self.__key_size = self.__crypto_certificate.public_key().key_size
            self.__certificate_expiration = self.__crypto_certificate.not_valid_after
            self.__start_certificate_validate = self.__crypto_certificate.not_valid_before
            self.__check_pubkey_type()
            if self.__certificate.has_expired():
                self.__errors.append(ExceptionCertificate.CERTIFICATE_EXPIRED)
        else:
            raise Exception('HTTPSInspectorError(__define_certificate_information__):the crypto certificate is null')

    def __get_issuer__(self):
        if self.__crypto_certificate is not None:
            try:
                self.__issuer = self.__crypto_certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                self.__issuer = None
                self.__errors.append(ExceptionCertificate.NO_ISSUER)
        else:
            raise Exception('HTTPSInspectorError(__get_issuer__): the crypto certificate is null')

    def __get_subject__(self):
        if self.__crypto_certificate is not None:
            try:
                self.__subject = self.__crypto_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                self.__error_no_subject = False
            except Exception:
                self.__subject = None
                self.__errors.append(ExceptionCertificate.NO_SUBJECT)
        else:
            raise Exception('HTTPSInspectorError(__get_subject__): the crypto certificate is null')

    def __verify_errors_in_certificate__(self):
        self.__is_valid_common_name__()
        try:
            requests.head(f'https://{self.__url_hostname}')
        except Exception as e:
            try:
                self.__errors.append(e.args[0].reason.args[0].verify_message)
            except Exception as er:
                self.__errors.append(str(e.args[0].reason.args[0]))
        self.__is_valid_certificate__()

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
                self.__errors.append(ExceptionCertificate.COMMON_NAME_INVALID)

    def __is_valid_certificate__(self):
        if len(self.__errors) != 0:
            self.__is_valid_certificate = False
        else:
            self.__is_valid_certificate = True

    def __get_certificate__(self):
        self.__connect_to_socket__()
        if self.__sock_ssl is not None:
            self.__certificate = self.__sock_ssl.get_peer_certificate()
            self.__crypto_certificate = self.__certificate.to_cryptography()
        else:
            raise Exception("HTTPSInspectorError(__get_certificate__): don't exist a connection")
        self.__close_socket_connection__()

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
            raise Exception(
                "HTTPSInspectorError(__connect_to_socket__): can't establish a connection because the hostname is null")

    def __close_socket_connection__(self):
        if self.__sock_ssl is not None:
            self.__sock_ssl.close()
            self.__sock.close()
        else:
            raise Exception("HTTPSInspectorError(__close_socket_connection__): don't exist a connection")

    def __has_https__(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((self.__url_hostname, 443))
            sock.shutdown(socket.SHUT_RDWR)
            return True
        except Exception:
            return False
        finally:
            sock.close()


class ExceptionCertificate:
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    NO_SUBJECT = "NO_SUBJECT"
    COMMON_NAME_INVALID = "COMMON_NAME_INVALID"
    NO_ISSUER = "NO_ISSUER"

    def __setattr__(self, *_):
        raise Exception("Tried to change the value of a constant")
