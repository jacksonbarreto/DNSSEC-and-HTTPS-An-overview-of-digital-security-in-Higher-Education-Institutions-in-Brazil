import unittest

from dnssec.DNSSecValidator import DNSSecValidator


class MyTestCase(unittest.TestCase):
    def test_Domain_without_DNSSEC(self):
        dnssec_domain = DNSSecValidator('ipp.pt')
        dnssec_domain.validator()
        dnssec_info = dnssec_domain.get_information()
        self.assertEqual(dnssec_info['has_dnssec'], False)
        self.assertEqual(dnssec_info['dnssec_is_valid'], False)

    def test_Domain_with_DNSSEC(self):
        dnssec_domain = DNSSecValidator('fccn.pt')
        dnssec_domain.validator()
        dnssec_info = dnssec_domain.get_information()
        self.assertEqual(dnssec_info['has_dnssec'], True)
        self.assertEqual(dnssec_info['dnssec_is_valid'], True)

    def test_URL_with_DNSSEC(self):
        dnssec_domain = DNSSecValidator('https://www.fccn.pt')
        dnssec_domain.validator()
        dnssec_info = dnssec_domain.get_information()
        self.assertEqual(dnssec_info['has_dnssec'], True)
        self.assertEqual(dnssec_info['dnssec_is_valid'], True)

    def test_URL_without_DNSSEC(self):
        dnssec_domain = DNSSecValidator('https://www.ipp.pt')
        dnssec_domain.validator()
        dnssec_info = dnssec_domain.get_information()
        self.assertEqual(dnssec_info['has_dnssec'], False)
        self.assertEqual(dnssec_info['dnssec_is_valid'], False)


if __name__ == '__main__':
    unittest.main()
