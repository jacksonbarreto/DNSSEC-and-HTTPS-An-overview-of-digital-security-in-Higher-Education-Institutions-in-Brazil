import dns.resolver
from tldextract import extract


class DNSSecInspector:
    def __init__(self, uri):
        self.__domain = None
        self.__get_domain__(uri)
        self.__nameserver = None
        self.__ns_ip_address = None
        self.__sec_answer = None
        self.__algorithm_name = None
        self.__has_dnssec = False
        self.__dnssec_is_valid = False
        self.__resolver = None

    def inspect(self):
        self.__get_ns()
        if self.__has_dnssec__():
            self.__has_dnssec = True
            if self.__dnssec_is_valid__():
                self.__dnssec_is_valid = True
                self.__set_algorithm_name__()
        return self

    def __get_domain__(self, domain_name_raw):
        _, td_location, tsu_location = extract(domain_name_raw)
        domain = f"{td_location}.{tsu_location}"
        self.__domain = domain

    def __get_ns(self):
        if self.__domain is not None:
            try:
                self.__nameserver = \
                    self.__get_resolver__().resolve(self.__domain, dns.rdatatype.NS, raise_on_no_answer=False).rrset[
                        0].to_text()
                self.__ns_ip_address = \
                    self.__get_resolver__().resolve(self.__nameserver, dns.rdatatype.A, raise_on_no_answer=False).rrset[
                        0].to_text()
            except Exception:
                return

    def __set_algorithm_name__(self):
        if self.__sec_answer is not None:
            dns_key_text = self.__sec_answer.rrset[0].to_text()
            algorithm_code = dns_key_text.split(" ")[2]
            self.__algorithm_name = dns.dnssec.algorithm_from_text(algorithm_code).name

    @staticmethod
    def __get_resolver__(nameserver='8.8.8.8'):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ([nameserver])
        resolver.lifetime = 10
        resolver.use_edns(0, dns.flags.CD | dns.flags.DO | dns.flags.RD, 4096)
        return resolver

    def get_information(self):
        return {
            "dnssec_domain": self.__domain,
            "dnssec_nameserver": self.__nameserver,
            "has_dnssec": self.__has_dnssec,
            "dnssec_is_valid": self.__dnssec_is_valid,
            "dnssec_algorithm": self.__algorithm_name
        }

    def __has_dnssec__(self):
        if self.__domain is not None:
            try:
                self.__sec_answer = self.__get_resolver__(self.__ns_ip_address).resolve(self.__domain,
                                                                                        dns.rdatatype.DNSKEY,
                                                                                        raise_on_no_answer=False)
                if len(self.__sec_answer) == 2:
                    return True
                else:
                    return False
            except Exception:
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
        except Exception:
            return False
