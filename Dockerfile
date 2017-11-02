FROM python:2.7-alpine

RUN mkdir -p /pypki 
WORKDIR /pypki/

COPY . /pypki

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev bash \
&& pip install  pyOpenSSL \
&& easy_install . 

#ENV CA_DN="CA_default" 

CMD python pki_web.py