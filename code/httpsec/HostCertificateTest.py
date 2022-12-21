import unittest

from httpsec.HTTPSInspector import HTTPSInspector


class MyTestCase(unittest.TestCase):
    def test_certificate_expired(self):
        hosts = ['https://expired.badssl.com/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_subject_different_from_host(self):
        hosts = ['https://wrong.host.badssl.com/', 'http://www.faflor.com.br/', 'http://esamazabaetetuba.com.br/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_invalid_by_no_subject(self):
        hosts = ['https://no-subject.badssl.com/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_invalid_by_no_common_name(self):
        hosts = ['https://no-common-name.badssl.com/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_ok(self):
        hosts = ['http://www.fva.com.br/', 'ipp.pt', 'itau.com.br', 'ind.millenniumbcp.pt']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, True)

    def test_certificate_valid_for_multiples_subdomain(self):
        hosts = ['https://www.uninassau.edu.br/institucional/caruaru/',
                 'https://portal.estacio.br/unidades/centro-universit%C3%A1rio-est%C3%A1cio-do-recife/',
                 'https://ages.edu.br/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, True)

    def test_redirect_forced_False(self):
        hosts = ['https://novafaculdadedegoiana.com.br/site/', 'http://fest.edu.br/',
                 'https://www.faflor.com.br/', ]
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['forced_redirect_to_https']
            self.assertEqual(certificate_valid, False)

    def test_redirect_forced_True(self):
        hosts = ['http://www.ipvc.pt/', 'ipp.pt', 'http://www.santander.pt/', 'ind.millenniumbcp.pt']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['forced_redirect_to_https']
            self.assertEqual(certificate_valid, True)

    def test_host_without_https(self):
        host = 'www.fameta.edu.br'
        host_info = HTTPSInspector(host)
        host_info.inspect()
        certificate_valid = host_info.get_host_certificate_information()['has_https']
        self.assertEqual(certificate_valid, False)

    def test_invalid_certificates(self):
        hosts = ['https://dh1024.badssl.com/', 'https://dh512.badssl.com/', 'https://dh480.badssl.com/']
        for host in hosts:
            host_info = HTTPSInspector(host)
            host_info.inspect()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_host_with_security_headers(self):
        host = 'www.utad.pt'
        host_inspect = HTTPSInspector(host)
        host_inspect.inspect()
        host_info = host_inspect.get_host_certificate_information()
        self.assertIsNot('', host_info['X-Frame-Options'])
        self.assertIsNot('', host_info['X-Content-Type-Options'])
        self.assertIsNot('', host_info['X-XSS-Protection'])

    def test_host_without_security_headers(self):
        host = 'www.ipvc.pt'
        host_inspect = HTTPSInspector(host)
        host_inspect.inspect()
        host_info = host_inspect.get_host_certificate_information()
        self.assertEqual('', host_info['X-Frame-Options'])
        self.assertEqual('', host_info['X-Content-Type-Options'])
        self.assertEqual('', host_info['X-XSS-Protection'])

    def test_public_key_type_ECC(self):
        host = 'https://ecc256.badssl.com/'
        host_inspect = HTTPSInspector(host)
        host_inspect.inspect()
        host_info = host_inspect.get_host_certificate_information()
        self.assertEqual('EllipticCurvePublicKey', host_info['public_key_type'])

    def test_public_key_type_RSA(self):
        host = 'https://www.fva.com.br/'
        host_inspect = HTTPSInspector(host)
        host_inspect.inspect()
        host_info = host_inspect.get_host_certificate_information()
        self.assertEqual('RSAPublicKey', host_info['public_key_type'])


if __name__ == '__main__':
    unittest.main()
