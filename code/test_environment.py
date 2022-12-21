from dnssec.DNSSecInspector import DNSSecInspector
from httpsec.HTTPSInspector import HTTPSInspector

if __name__ == '__main__':

    # url = 'www.cm-agueda.pt'

    url = 'www.cm-albergaria.pt'


    for x in range(100):
        print(x)
        print(HTTPSInspector(url).inspect().get_information())
        print(DNSSecInspector(url).inspect().get_information())
