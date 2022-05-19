import dns.resolver
from tldextract import extract


class DNSSecValidator:
    def __init__(self, host):
        self.__domain = self.__get_domain__(host)
        self.__nameserver = None
        self.__ns_ip_address = None
        self.__sec_answer = None
        self.__algorithm_name = None
        self.__has_dnssec = False
        self.__dnssec_is_valid = False
        self.__resolver = None

    def validator(self):
        self.__get_ns()
        if self.__has_dnssec__():
            self.__has_dnssec = True
            if self.__dnssec_is_valid__():
                self.__dnssec_is_valid = True
                self.__set_algorithm_name__()

    def __get_domain__(self, url_raw):
        _, td_location, tsu_location = extract(url_raw)
        domain = f"{td_location}.{tsu_location}"
        return domain

    def __get_ns(self):
        if self.__domain is not None:
            self.__nameserver = \
                self.__get_resolver__().resolve(self.__domain, dns.rdatatype.NS, raise_on_no_answer=False).rrset[
                    0].to_text()
            self.__ns_ip_address = \
                self.__get_resolver__().resolve(self.__nameserver, dns.rdatatype.A, raise_on_no_answer=False).rrset[
                    0].to_text()

    def __set_algorithm_name__(self):
        if self.__sec_answer is not None:
            dns_key_text = self.__sec_answer.rrset[0].to_text()
            algorithm_code = dns_key_text.split(" ")[2]
            self.__algorithm_name = dns.dnssec.algorithm_from_text(algorithm_code).name

    def __get_resolver__(self, nameserver='8.8.8.8'):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ([nameserver])
        resolver.use_edns(0, dns.flags.DO, 4096)
        return resolver

    def get_information(self):
        return {
            "hostname": self.__domain,
            "has_dnssec": self.__has_dnssec,
            "dnssec_is_valid": self.__dnssec_is_valid,
            "algorithm_name": self.__algorithm_name
        }

    def __has_dnssec__(self):
        if self.__domain is not None:
            self.__sec_answer = self.__get_resolver__().resolve(self.__domain, dns.rdatatype.DNSKEY,
                                                                raise_on_no_answer=False)
            if len(self.__sec_answer) == 2:
                return True
            else:
                return False

    def __dnssec_is_valid__(self):
        try:
            q_name = dns.name.from_text(self.__domain)
            server = self.__get_resolver__(self.__ns_ip_address).resolve(self.__nameserver, dns.rdatatype.A).rrset[
                0].to_text()
            q_sec = dns.message.make_query(q_name, dns.rdatatype.DNSKEY, want_dnssec=True)
            r_sec = dns.query.udp(q_sec, server)
            a_sec = r_sec.answer
            dns.dnssec.validate(a_sec[0], a_sec[1], {q_name: a_sec[0]})
            return True
        except dns.dnssec.ValidationFailure:
            return False
