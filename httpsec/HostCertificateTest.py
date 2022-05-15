import unittest

from httpsec.HostCertificate import HostCertificate


class MyTestCase(unittest.TestCase):
    def test_certificate_expired(self):
        hosts = ['https://expired.badssl.com/']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            certificate_has_expired = host_info.get_host_certificate_information()['certificate_has_expired']
            self.assertEqual(certificate_valid, False)
            self.assertEqual(certificate_has_expired, True)

    def test_subject_different_from_host(self):
        hosts = ['https://wrong.host.badssl.com/', 'http://www.faflor.com.br/', 'http://esamazabaetetuba.com.br/']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_invalid_by_no_subject(self):
        hosts = ['https://no-subject.badssl.com/']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_invalid_by_no_common_name(self):
        hosts = ['https://no-common-name.badssl.com/']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, False)

    def test_certificate_ok(self):
        hosts = ['http://www.fva.com.br/', 'ipp.pt', 'itau.com.br', 'ind.millenniumbcp.pt']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, True)

    def test_certificate_valid_for_multiples_subdomain(self):
        hosts = ['https://ages.edu.br/', 'https://www.uninassau.edu.br/institucional/caruaru/',
                 'https://portal.estacio.br/unidades/centro-universit%C3%A1rio-est%C3%A1cio-do-recife/',
                 'https://ages.edu.br/']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['certificate_valid']
            self.assertEqual(certificate_valid, True)

    def test_redirect_forced_False(self):
        hosts = ['https://novafaculdadedegoiana.com.br/site/', 'http://fest.edu.br/',
                 'https://www.faflor.com.br/', ]
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['forced_redirect_to_https']
            self.assertEqual(certificate_valid, False)

    def test_redirect_forced_True(self):
        hosts = ['http://www.ipvc.pt/', 'ipp.pt', 'http://www.santander.pt/', 'ind.millenniumbcp.pt']
        for host in hosts:
            host_info = HostCertificate(host)
            host_info.collect_certificate_information()
            certificate_valid = host_info.get_host_certificate_information()['forced_redirect_to_https']
            self.assertEqual(certificate_valid, True)


if __name__ == '__main__':
    unittest.main()
