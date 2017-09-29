FROM python:2.7-alpine

RUN mkdir -p /PKI/pypki 
WORKDIR /PKI/pypki/

COPY . /PKI/pypki

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev easy-rsa \
&& ln -s /usr/share/easy-rsa/easyrsa /bin/easyrsa \
&& pip install  pyOpenSSL \
&& cd /PKI && easy_install pypki \
&& cp pypki/openssl-1.0.cnf . \
&& easyrsa init-pki 
# easyrsa build-ca 
# easyrsa gen-dh
# easyrsa gen-crl

ENV CA_DN="CA_default" \


CMD python pki_web.py