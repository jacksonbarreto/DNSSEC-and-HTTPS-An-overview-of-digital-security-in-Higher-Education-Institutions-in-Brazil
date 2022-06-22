--select * from  ies_sec_info;


SELECT category, count(*) as total_ies, CONVERT(decimal(10,2), (cast(count(*) as real) * 100/2528)) as percentual
	FROM ies_sec_info
	GROUP BY category;

-- STATES WITH PUBLIC AND PRIVATE INSTITUTIONS
Declare @total_ies_pub int = 320
Declare @total_ies_pri int = 2208
Declare @total_ies int = 2528
Declare @ies_pub Table(state varchar(255), public_total int, public_percent real);
Declare @ies_privada Table(state varchar(255), private_total int, private_percent real);

INSERT INTO @ies_pub
SELECT o.state, count(*) as publica_total, CONVERT(decimal(10,2), cast(count(*) as real) * cast(100 as real)/t_ies_state) as publica_percent
FROM ies_sec_info as o 
INNER JOIN (select state, count(*) as t_ies_state from ies_sec_info group by state) as ies on o.state = ies.state
WHERE category like 'Publica' 
GROUP BY o.state, t_ies_state ORDER BY state;

INSERT INTO @ies_privada
SELECT o.state, count(*) as privada_total, (cast(count(*) as real) * 100)/t_ies_state as privada_percent
FROM ies_sec_info as o 
INNER JOIN (select state, count(*) as t_ies_state from ies_sec_info group by state) as ies on o.state = ies.state
WHERE category like 'Privada' 
GROUP BY o.state, t_ies_state ORDER BY state;

SELECT o.state, count(*) as global_total, CONVERT(decimal(10,2), (cast(count(*) as real) * 100)/@total_ies) as global_percent, public_total, public_percent, private_total, private_percent
FROM ies_sec_info as o 
INNER JOIN @ies_pub as pub on pub.state = o.state
INNER JOIN @ies_privada as priv on priv.state = o.state
	GROUP BY o.state, public_total, public_percent, private_total, private_percent ORDER BY state;

-- DNSSEC

SELECT o.state, count(*) as total, total_without_dnssec, 
CONVERT(decimal(10,2), CAST(total_without_dnssec as real) *100 / count(*)) as total_without_dnssec_percent, total_with_dnssec_pub, 
CONVERT(decimal(10,2), CAST(total_with_dnssec_pub as real) *100 / count(*)) as total_with_dnssec_pub_percent,
total_with_dnssec_priv, CONVERT(decimal(10,2), CAST(total_with_dnssec_priv as real) * 100 / count(*)) as total_with_dnssec_priv_percent
from ies_sec_info as o
INNER JOIN (
SELECT state, count(*) as total_without_dnssec
from ies_sec_info
WHERE has_dnssec = 'False'
GROUP BY state) as w on w.state = o.state
 Left JOIN (
SELECT state, count(*) as total_with_dnssec_pub
from ies_sec_info
WHERE has_dnssec = 'True' and category = 'Publica'
GROUP BY state) as pub on pub.state = o.state
 left JOIN (
SELECT state, count(*) as total_with_dnssec_priv
from ies_sec_info
WHERE has_dnssec = 'True' and category = 'Privada'
GROUP BY state) as priv on priv.state = o.state
GROUP BY o.state, total_without_dnssec, total_with_dnssec_pub, total_with_dnssec_priv ORDER BY state;

--HTTPS

SELECT o.state, count(*) as total, 
http_only, 
CONVERT(decimal(10,2), CAST(http_only as real) * 100 / count(*)) as http_only_percent, 
with_https,
CONVERT(decimal(10,2), CAST(with_https as real) * 100 / count(*)) as with_https_percent,
redirect_to_https, 
CONVERT(decimal(10,2), CAST(redirect_to_https as real) * 100 / count(*)) as redirect_to_https_percent, 
redirect_to_same_domain, 
CONVERT(decimal(10,2), CAST(redirect_to_same_domain as real) * 100 / count(*)) as redirect_to_same_domain_percent, 
certificate_valid,
CONVERT(decimal(10,2), CAST(certificate_valid as real) * 100 / count(*)) as certificate_valid_percent
from ies_sec_info as o
LEFT JOIN (SELECT state, count(*) as http_only from ies_sec_info where has_https = 'False' GROUP BY state) as w on w.state = o.state
LEFT JOIN (SELECT state, count(*) as with_https from ies_sec_info where has_https = 'True' GROUP BY state) as n on n.state = o.state
LEFT JOIN (SELECT state, count(*) as redirect_to_https from ies_sec_info where forced_redirect_to_https = 'True' GROUP BY state) as p on p.state = o.state
LEFT JOIN (SELECT state, count(*) as redirect_to_same_domain from ies_sec_info where https_redirect_to_same_domain = 'True' GROUP BY state) as q on q.state = o.state
LEFT JOIN (SELECT state, count(*) as certificate_valid from ies_sec_info where https_certificate_valid = 'True' GROUP BY state) as r on r.state = o.state
GROUP BY o.state, http_only, with_https, redirect_to_https, redirect_to_same_domain, certificate_valid ORDER BY o.state;

-- CCERTIFICATE USED BY CA
SELECT o.issuer, 
(SELECT count(distinct issuer) from ies_sec_info WHERE issuer <> '' ) as total_ca,
(SELECT count(*) from ies_sec_info WHERE issuer <> '') as sum_global,
count(*) as global,
CONVERT(decimal(10,2), count(*) * CAST(100 as real) / (SELECT count(*) from ies_sec_info WHERE issuer <> '') ) as global_percent,
total_public, 
CONVERT(decimal(10,2), CAST(total_public as real) * 100 / (SELECT count(*) from ies_sec_info WHERE issuer <> '')) as total_public_percent, 
total_private,
CONVERT(decimal(10,2), CAST(total_private as real) * 100 / (SELECT count(*) from ies_sec_info WHERE issuer <> '')) as total_private_percent
FROM ies_sec_info as o
LEFT JOIN (SELECT issuer, count(*) as total_public FROM ies_sec_info WHERE issuer <> '' and category = 'Publica' GROUP BY issuer) as p on o.issuer = p.issuer 
LEFT JOIN (SELECT issuer, count(*) as total_private FROM ies_sec_info WHERE issuer <> '' and category = 'Privada' GROUP BY issuer) as q on o.issuer = q.issuer
where o.issuer <> ''
GROUP BY o.issuer, total_public, total_private
ORDER BY global DESC;


-- KEY SIZE BY STATE

SELECT o.state, 
total,
without_ssl,
CONVERT(decimal(10,2), CAST(without_ssl as real) * 100 / total) as without_ssl_percent,
count(*) as with_ssl,
CONVERT(decimal(10,2), count(*) * CAST(100 as real) / total) as with_ssl_percent,
size_2048,
CONVERT(decimal(10,2), CAST(size_2048 as real) * 100 / total) as size_2048_percent,
size_4096,
CONVERT(decimal(10,2), CAST(size_4096 as real) * 100 / total) as size_4096_percent,
size_256,
CONVERT(decimal(10,2), CAST(size_256 as real) * 100 / total) as size_256_percent
FROM ies_sec_info as o
LEFT JOIN (SELECT state, count(*) as size_2048 FROM ies_sec_info WHERE https_key_size = 2048 GROUP BY state) as p on p.state = o.state
LEFT JOIN (SELECT state, count(*) as size_4096 FROM ies_sec_info WHERE https_key_size = 4096 GROUP BY state) as q on q.state = o.state
LEFT JOIN (SELECT state, count(*) as size_256 FROM ies_sec_info WHERE https_key_size = 256 GROUP BY state) as r on r.state = o.state
LEFT JOIN (SELECT state, count(*) as total FROM ies_sec_info GROUP BY state) as s on s.state = o.state
LEFT JOIN (SELECT state, count(*) as without_ssl FROM ies_sec_info WHERE has_https = 'False' GROUP BY state) as t on t.state = o.state
WHERE has_https = 'True'
GROUP BY o.state, size_2048, size_4096, size_256, total, without_ssl
ORDER BY o.state;

-- Algorithms by state
SELECT o.state, 
total,
without_ssl,
CONVERT(decimal(10,2), CAST(without_ssl as real) * 100 / total) as without_ssl_percent,
rsa,
CONVERT(decimal(10,2), CAST(rsa as real) * 100 / total) as rsa_percent,
ecc,
CONVERT(decimal(10,2), CAST(ecc as real) * 100 / total) as ecc_percent
FROM ies_sec_info as o
LEFT JOIN (SELECT state, count(*) as rsa FROM ies_sec_info WHERE public_key_type = 'RSAPublicKey' GROUP BY state) as q on q.state = o.state
LEFT JOIN (SELECT state, count(*) as ecc FROM ies_sec_info WHERE public_key_type = 'EllipticCurvePublicKey' GROUP BY state) as r on r.state = o.state
LEFT JOIN (SELECT state, count(*) as total FROM ies_sec_info GROUP BY state) as s on s.state = o.state
LEFT JOIN (SELECT state, count(*) as without_ssl FROM ies_sec_info WHERE has_https = 'False' GROUP BY state) as t on t.state = o.state
GROUP BY o.state, without_ssl, total, rsa, ecc
ORDER BY o.state;



-- TLS version

SELECT o.state, 
total,
without_ssl,
CONVERT(decimal(10,2), CAST(without_ssl as real) * 100 / total) as without_ssl_percent,
TLSv11,
CONVERT(decimal(10,2), CAST(TLSv11 as real) * 100 / total) as TLSv11_percent,
TLSv12,
CONVERT(decimal(10,2), CAST(TLSv12 as real) * 100 / total) as TLSv12_percent,
TLSv13,
CONVERT(decimal(10,2), CAST(TLSv13 as real) * 100 / total) as TLSv13_percent
FROM ies_sec_info as o
LEFT JOIN (SELECT state, count(*) as TLSv11 FROM ies_sec_info WHERE https_protocol_version_name = 'TLSv1.1' GROUP BY state) as p on p.state = o.state
LEFT JOIN (SELECT state, count(*) as TLSv12 FROM ies_sec_info WHERE https_protocol_version_name = 'TLSv1.2' GROUP BY state) as q on q.state = o.state
LEFT JOIN (SELECT state, count(*) as TLSv13 FROM ies_sec_info WHERE https_protocol_version_name = 'TLSv1.3' GROUP BY state) as r on r.state = o.state
LEFT JOIN (SELECT state, count(*) as total FROM ies_sec_info GROUP BY state) as s on s.state = o.state
LEFT JOIN (SELECT state, count(*) as without_ssl FROM ies_sec_info WHERE has_https = 'False' GROUP BY state) as t on t.state = o.state
GROUP BY o.state, without_ssl, total, TLSv11, TLSv12, TLSv13
ORDER BY o.state;

--security headers
SELECT o.state, count(*) as total,
x_frame,
CONVERT(decimal(10,2), CAST(x_frame as real) * 100 / count(*)) as x_frame_percent,
x_frame_public,
CONVERT(decimal(10,2), CAST(x_frame_public as real) * 100 / count(*)) as x_frame_public_percent, 
x_frame_private,
CONVERT(decimal(10,2), CAST(x_frame_private as real) * 100 / count(*)) as x_frame_private_percent,
x_content,
CONVERT(decimal(10,2), CAST(x_content as real) * 100 / count(*)) as x_content_percent,
x_content_public,
CONVERT(decimal(10,2), CAST(x_content_public as real) * 100 / count(*)) as x_content_public_percent,
x_content_private,
CONVERT(decimal(10,2), CAST(x_content_private as real) * 100 / count(*)) as x_content_private_percent,
x_xss, 
CONVERT(decimal(10,2), CAST(x_xss as real) * 100 / count(*)) as x_xss_percent,
x_xss_public, 
CONVERT(decimal(10,2), CAST(x_xss_public as real) * 100 / count(*)) as x_xss_public_percent,
x_xss_private,
CONVERT(decimal(10,2), CAST(x_xss_private as real) * 100 / count(*)) as x_xss_private_percent
FROM ies_sec_info as o
LEFT JOIN (SELECT state, count(*) as x_frame FROM ies_sec_info WHERE [X-Frame-Options] <> '' GROUP BY state) as a on a.state = o.state
LEFT JOIN (SELECT state, count(*) as x_frame_public FROM ies_sec_info WHERE [X-Frame-Options] <> '' AND category = 'Publica' GROUP BY state) as b on b.state = o.state
LEFT JOIN (SELECT state, count(*) as x_frame_private FROM ies_sec_info WHERE [X-Frame-Options] <> '' AND category = 'Privada' GROUP BY state)  as c on c.state = o.state
LEFT JOIN (SELECT state, count(*) as x_content FROM ies_sec_info WHERE [X-Content-Type-Options] <> '' GROUP BY state) as d on d.state = o.state
LEFT JOIN (SELECT state, count(*) as x_content_public FROM ies_sec_info WHERE [X-Content-Type-Options] <> '' AND category = 'Publica' GROUP BY state) as e on e.state = o.state
LEFT JOIN (SELECT state, count(*) as x_content_private FROM ies_sec_info WHERE [X-Content-Type-Options] <> '' AND category = 'Privada' GROUP BY state)  as f on f.state = o.state
LEFT JOIN (SELECT state, count(*) as x_xss FROM ies_sec_info WHERE [X-XSS-Protection] <> '' GROUP BY state) as g on g.state = o.state
LEFT JOIN (SELECT state, count(*) as x_xss_public FROM ies_sec_info WHERE [X-XSS-Protection] <> '' AND category = 'Publica' GROUP BY state) as h on h.state = o.state
LEFT JOIN (SELECT state, count(*) as x_xss_private FROM ies_sec_info WHERE [X-XSS-Protection] <> '' AND category = 'Privada' GROUP BY state)  as i on i.state = o.state
GROUP BY o.state, x_frame, x_frame_public, x_frame_private, x_content, x_content_public, x_content_private, x_xss, x_xss_public, x_xss_private
ORDER BY o.state;



-- IES suportam a tecnologia DNSSEC
SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_dnssec
from ies_sec_info as o
WHERE has_dnssec = 'True') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info))) as ies_in_brazil_with_dnssec 

-- IES publicas suportam a tecnologia DNSSEC
SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_dnssec
from ies_sec_info as o
WHERE has_dnssec = 'True' AND category = 'Publica') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info))) as ies_public_with_dnssec 

--IES não utilizam certificado SSL 
SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_without_https
from ies_sec_info as o
WHERE has_https = 'False') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info))) as ies_in_brazil_without_https 

--IES utilizam certificado SSL Mas não obrigam o uso
SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_without_https
from ies_sec_info as o
WHERE has_https = 'True' AND forced_redirect_to_https = 'False') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_without_https 

--Autoridade Certificadora 
SELECT issuer, count(*) as total_ca 
FROM ies_sec_info
GROUP BY issuer
ORDER BY total_ca DESC;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_CA_R3
from ies_sec_info as o
WHERE issuer = 'R3') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info))) as ies_in_brazil_with_CA_R3;

--Autoridade Certificadora nas privadas 
SELECT issuer, count(*) as total_ca 
FROM ies_sec_info
WHERE category = 'Privada'
GROUP BY issuer
ORDER BY total_ca DESC;


SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_CA_R3
from ies_sec_info as o
WHERE issuer = 'R3' AND category = 'Privada') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE category = 'Privada'))) as ies_in_brazil_with_CA_R3;

--cifras e algoritmos TLS
SELECT https_key_size, count(*) as total_key
FROM ies_sec_info
WHERE has_https = 'True'
GROUP BY https_key_size
ORDER BY total_key DESC;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_key_size_2048
from ies_sec_info as o
WHERE https_key_size = 2048) * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_key_size_2048;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_rsa
from ies_sec_info as o
WHERE public_key_type = 'RSAPublicKey') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_rsa;

--Versão do TLS
SELECT https_protocol_version_name, count(*) as total_protocol
FROM ies_sec_info
WHERE has_https = 'True'
GROUP BY https_protocol_version_name
ORDER BY total_protocol DESC;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies_with_rsa
from ies_sec_info as o
WHERE https_protocol_version_name = 'TLSv1.2') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_rsa;

--headers security
SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies
from ies_sec_info as o
WHERE has_https = 'True' AND [X-Content-Type-Options] <> '') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_X_Content_Type_Options;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies
from ies_sec_info as o
WHERE has_https = 'True' AND [X-Frame-Options] <> '') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_X_Frame_Options;

SELECT CONVERT(decimal(10,2), ((SELECT count(*) as total_ies
from ies_sec_info as o
WHERE has_https = 'True' AND [X-XSS-Protection] <> '') * CAST(100 as real) / (SELECT count(*) FROM ies_sec_info WHERE has_https = 'True'))) as ies_in_brazil_with_X_xxs_protection;