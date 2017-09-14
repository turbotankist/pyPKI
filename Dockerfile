FROM python:2.7-alpine

RUN mkdir -p /PKI/pypki  && mkdir /PKI/pki-root
WORKDIR /PKI

COPY . /PKI/pypki

RUN cd /PKI && easy_install pypki \
&& pip install cherrypy-wsgiserver \
&& cp pypki/openssl.cnf pki-root \
&& cp -r pypki/RootCA pki-root \
&& cp -r pypki/ca pki-root

CMD python /PKI/pypki/pki_web.py