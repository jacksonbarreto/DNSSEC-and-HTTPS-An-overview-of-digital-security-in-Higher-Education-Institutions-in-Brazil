from httpsec.HostCertificate import HostCertificate

if __name__ == '__main__':
    hosts = ['https://www.fva.com.br/', 'ipp.pt', 'itau.com.br', 'ind.millenniumbcp.pt',
             'https://www.uninassau.edu.br/institucional/caruaru/',
             'https://portal.estacio.br/unidades/centro-universit%C3%A1rio-est%C3%A1cio-do-recife/',
             'https://ecc256.badssl.com/',
             'https://tls-v1-0.badssl.com/',
             'https://tls-v1-1.badssl.com/',
             'https://revoked.badssl.com/',
             'https://expired.badssl.com/',
             'https://wrong.host.badssl.com/',
             'https://no-common-name.badssl.com/',
             'http://esamazabaetetuba.com.br/',
             'http://www.ccomgex.eb.mil.br/',
             'https://www.pitagoras.com.br/unidade/faculdade-pitagoras-de-medicina-de-codo/',
             'http://novafaculdadedegoiana.com.br/site/',
             'http://fest.edu.br/',
             'http://www.faflor.com.br/',
             'https://ages.edu.br/',
             ]

    for host in hosts:
        host_info = HostCertificate(host)
        host_info.collect_certificate_information()
        print(host_info.get_host_certificate_information())
