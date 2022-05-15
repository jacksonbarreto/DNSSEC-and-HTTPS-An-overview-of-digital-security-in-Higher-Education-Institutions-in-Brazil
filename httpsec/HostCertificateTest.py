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


if __name__ == '__main__':
    unittest.main()
