from urllib.parse import urlparse

import idna
import socket
import requests
import urllib3

from OpenSSL import SSL
from cryptography.x509.oid import NameOID
from sslyze import ServerScanRequest, ServerNetworkLocation, ServerHostnameCouldNotBeResolved, Scanner, \
    ServerScanStatusEnum, ScanCommandAttemptStatusEnum, RobotScanResultEnum
from tldextract import extract
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import x25519


class HTTPSInspector:
    TIMEOUT_LIMIT = 5
    DEFAULT_HTTP_PORT = 443

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
        self.__ssl2 = None
        self.__ssl3 = None
        self.__tls1_0 = None
        self.__tls1_1 = None
        self.__tls1_2 = None
        self.__tls1_3 = None
        self.__is_vulnerable_to_heartbleed = None
        self.__is_vulnerable_to_ccs_injection = None
        self.__is_vulnerable_to_client_renegotiation_dos = None
        self.__supports_secure_renegotiation = None
        self.__supports_tls_compression = None
        self.__robot_attack = None
        self.__scanner_sslyze = None

    def inspect(self):
        urllib3.disable_warnings()

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

            # COMMENT: We could for security headers even if there's no SSL/TLS being used? In theory, these headers would be MITM'able, but they at least indicate some security awareness.
            self.__check_security_headers__()
            
            self.__define_certificate_information__()
            self.__verify_errors_in_certificate__()
            self.__define_supported_https_protocols__()
            self.__verify_vulnerabilities__()
        else:
            self.__has_https = False
        # COMMENT: We could also have a look at the cookies:
        # How many are being set? What flags do they have? (samesite, httponly, secure)
        return self

    def get_information(self):
        return {
            'has_https': self.__has_https,
            'host_ip_address': self.__host_ip_address,
            'protocol_version_name': self.__protocol_version_name,
            'forced_redirect_to_https': self.__forced_redirect_to_https,
            'https_redirect_to_same_domain': self.__https_redirect_to_same_domain,
            'X-Frame-Options': self.__x_frame,
            'X-Content-Type-Options': self.__x_content,
            'X-XSS-Protection': self.__x_xss,
            'certificate_valid': self.__is_valid_certificate,
            'certificate_version': self.__certificate_version,
            'issuer': self.__issuer,
            'subject': self.__subject,
            'certificate_algorithm_name': self.__algorithm_name,
            'key_size': self.__get_key_size__(),
            'certificate_public_key_type': self.__public_key_type,
            'start_certificate_validate': self.__start_certificate_validate,
            'certificate_expiration': self.__certificate_expiration,
            'ssl2': self.__ssl2,
            'ssl3': self.__ssl3,
            'tls1_0': self.__tls1_0,
            'tls1_1': self.__tls1_1,
            'tls1_2': self.__tls1_2,
            'tls1_3': self.__tls1_3,
            'is_vulnerable_to_heartbleed': self.__is_vulnerable_to_heartbleed,
            'is_vulnerable_to_ccs_injection': self.__is_vulnerable_to_ccs_injection,
            'is_vulnerable_to_client_renegotiation_dos': self.__is_vulnerable_to_client_renegotiation_dos,
            'supports_secure_renegotiation': self.__supports_secure_renegotiation,
            'supports_tls_compression': self.__supports_tls_compression,
            'robot_attack': self.__robot_attack,
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
            try:__url_hostname
                # COMMENT: Why HEAD instead of GET? 
                response = requests.head(f"https://{self.__url_hostname}", allow_redirects=False, verify=False,
                                         timeout=HTTPSInspector.TIMEOUT_LIMIT)
                headers = response.headers
                # COMMENT: How does requests handle header-capitalization? 
                # Is it normalized or do we need to use .lower()/.upper()?
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
                # COMMENT: What about other Websecurity headers (OWASP Web Sec Headers)
                # https://owasp.org/www-project-secure-headers/#div-headers
                # -> Content-Security-Policy, etc.
            except:
                self.__x_frame = "error in the request"
                self.__x_content = "error in the request"
                self.__x_xss = "error in the request"
        else:
            raise Exception('HTTPSInspectorError(__check_security_headers__): the hostname is null')

    def __has_forced_redirect_from_http_to_https__(self):
        if self.__url_hostname is not None:
            try:
                response = requests.head(f"http://{self.__url_hostname}", allow_redirects=False, verify=False,
                                         timeout=HTTPSInspector.TIMEOUT_LIMIT)
                if 300 <= response.status_code <= 308 and urlparse(response.headers['location']).scheme == 'https':
                    self.__location = response.headers['location']
                    return True
                else:
                    return False
                # COMMENT: Are there sites that do not use the location header and just use <meta..>-redirects? (I don't think so, but could consider this?)
            except:
                # COMMENT: Shouldn't this be an exception instead of "false", because in case of errors, we cannot tell.
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
        # COMMENT: Why use urlparse? Doesn't tldextract provide similar and more reliable functionality?
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
                self.__errors.append('HTTPSInspectorError(get_issuer): ' + ExceptionCertificate.NO_ISSUER)
        else:
            raise Exception('HTTPSInspectorError(__get_issuer__): the crypto certificate is null')

    def __get_subject__(self):
        if self.__crypto_certificate is not None:
            try:
                self.__subject = self.__crypto_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                self.__error_no_subject = False
            except Exception:
                self.__subject = None
                self.__errors.append('HTTPSInspectorError(get_subject): ' + ExceptionCertificate.NO_SUBJECT)
        else:
            raise Exception('HTTPSInspectorError(__get_subject__): the crypto certificate is null')

    def __verify_errors_in_certificate__(self):
        # COMMENT: The return value is not used? Why is this here?
        self.__is_valid_common_name__() 
        try:
            requests.head(f'https://{self.__url_hostname}', timeout=HTTPSInspector.TIMEOUT_LIMIT)
        except Exception as e:
            if hasattr(e.args[0].reason.args[0], 'verify_message'):
                self.__errors.append(e.args[0].reason.args[0].verify_message)
            else:
                self.__errors.append(str(e.args[0].reason.args[0]))

        self.__is_valid_certificate__()

    def __verify_common_name__(self):
        # COMMENT: Checks for self.__subject is not None?
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
        # COMMENT: There are some cases which are not covered:
        # verify_common_name(url_hostname, subject)
        # verify_common_name("www.baz.foobar.com.pl", "*.foobar.com") => None
        # verify_common_name("foobar.com", "*.foobar.com.pl") => None

    def __is_valid_common_name__(self):
        if self.__subject is not None:
            if not self.__verify_common_name__():
                self.__errors.append(ExceptionCertificate.COMMON_NAME_INVALID)

    def __is_valid_certificate__(self):
        # COMMENT: Maybe explicitly check for certificate-related errors? 
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
            self.__sock.connect((self.__url_hostname, HTTPSInspector.DEFAULT_HTTP_PORT))
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            ctx.check_hostname = False
            self.__host_ip_address = self.__sock.getpeername()[0]
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
        sock.settimeout(HTTPSInspector.TIMEOUT_LIMIT)
        try:
            sock.connect((self.__url_hostname, HTTPSInspector.DEFAULT_HTTP_PORT))
            sock.shutdown(socket.SHUT_RDWR)
            return True
        except ConnectionRefusedError:
            return False
        except Exception as e:
            raise e
        finally:
            sock.close()


    def __define_supported_https_protocols__(self):
        protocols = self.__check_supported_https_protocols__()

        for protocol in protocols:
            match protocol['protocol']:
                case 'SSLv2':
                    self.__ssl2 = protocol['supported']
                case 'SSLv3':
                    self.__ssl3 = protocol['supported']
                case 'TLSv10':
                    self.__tls1_0 = protocol['supported']
                case 'TLSv11':
                    self.__tls1_1 = protocol['supported']
                case 'TLSv12':
                    self.__tls1_2 = protocol['supported']
                case 'TLSv13':
                    self.__tls1_3 = protocol['supported']

    def __check_supported_https_protocols__(self):
        protocols = [{"protocol": 'SSLv2', "supported": False},
                     {"protocol": 'SSLv3', "supported": False},
                     {"protocol": 'TLSv10', "supported": False},
                     {"protocol": 'TLSv11', "supported": False},
                     {"protocol": 'TLSv12', "supported": False},
                     {"protocol": 'TLSv13', "supported": False}]
        # First create the scan requests for each server that we want to scan
        try:
            all_scan_requests = [
                ServerScanRequest(server_location=ServerNetworkLocation(hostname=str(self.__url_hostname))),
            ]
        except ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
            self.__errors.append("HTTPSInspectorError(check_supported_https_protocols): Error resolving the supplied hostnames")
            return

        # Then queue all the scans
        scanner = Scanner()
        scanner.queue_scans(all_scan_requests)
        # And retrieve and process the results for each server
        all_server_scan_results = []
        for server_scan_result in scanner.get_results():
            all_server_scan_results.append(server_scan_result)
            # Were we able to connect to the server and run the scan?
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                # No we weren't
                self.__errors.append("HTTPSInspectorError(check_supported_https_protocols): Could not connect")
                continue

            # Since we were able to run the scan, scan_result is populated
            assert server_scan_result.scan_result
            attempt = None
            for protocol in protocols:
                match protocol['protocol']:
                    case 'SSLv2':
                        attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
                    case 'SSLv3':
                        attempt = server_scan_result.scan_result.ssl_3_0_cipher_suites
                    case 'TLSv10':
                        attempt = server_scan_result.scan_result.tls_1_0_cipher_suites
                    case 'TLSv11':
                        attempt = server_scan_result.scan_result.tls_1_1_cipher_suites
                    case 'TLSv12':
                        attempt = server_scan_result.scan_result.tls_1_2_cipher_suites
                    case 'TLSv13':
                        attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
                if attempt is None:
                    return protocols
                if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    self.__errors.append('HTTPSInspectorError(check_supported_https_protocols): ' + attempt.error_reason)
                elif attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    attempt_result = attempt.result
                    assert attempt_result
                    if len(attempt_result.accepted_cipher_suites) > 0:
                        protocol['supported'] = True

            return protocols

    def __verify_vulnerabilities__(self):
        # First create the scan requests for each server that we want to scan
        try:
            all_scan_requests = [
                ServerScanRequest(server_location=ServerNetworkLocation(hostname=str(self.__url_hostname))),
            ]
        except ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
            self.__errors.append("HTTPSInspectorError(verify_vulnerabilities): Error resolving the supplied hostnames")
            return

        # Then queue all the scans
        scanner = Scanner()
        scanner.queue_scans(all_scan_requests)
        all_server_scan_results = []
        for server_scan_result in scanner.get_results():
            all_server_scan_results.append(server_scan_result)
            # Were we able to connect to the server and run the scan?
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                # No we weren't
                self.__errors.append("HTTPSInspectorError(verify_vulnerabilities): Could not connect")
                continue

            # Since we were able to run the scan, scan_result is populated
            assert server_scan_result.scan_result

            self.__is_vulnerable_to_heartbleed = server_scan_result.scan_result.heartbleed.result.is_vulnerable_to_heartbleed
            self.__is_vulnerable_to_ccs_injection = server_scan_result.scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection
            self.__is_vulnerable_to_client_renegotiation_dos = server_scan_result.scan_result.session_renegotiation.result.is_vulnerable_to_client_renegotiation_dos
            self.__supports_secure_renegotiation = server_scan_result.scan_result.session_renegotiation.result.supports_secure_renegotiation
            self.__supports_tls_compression = server_scan_result.scan_result.tls_compression.result.supports_compression
            robot_result_scanner = server_scan_result.scan_result.robot.result
            if hasattr(robot_result_scanner, 'robot_result'):
                self.__robot_attack = robot_result_scanner.robot_result.value


class ExceptionCertificate:
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    NO_SUBJECT = "NO_SUBJECT"
    COMMON_NAME_INVALID = "COMMON_NAME_INVALID"
    NO_ISSUER = "NO_ISSUER"

    def __setattr__(self, *_):
        raise Exception("Tried to change the value of a constant")
