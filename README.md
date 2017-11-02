# Pypki

A Frontend for openssl
Based on webpy python framework

RootCA folder to mount is /pypki/pki

## requirements:
1. Python2.7 (There are some problems with 3)
2. 

## install:
pip install  pyOpenSSL
easy_install .
### run:
python pki_web.py

## run in docker:
docker build -t pypki .
docker run --name pypki --restart always -v YOUR_SECURE_PATH:/pypki/pki -p 443:8080 -d pypki

## Quik start 
enter to **https**://localhosthost:8080 (or without 8080 if using  -p 443:8080)

If there is not pki - you will been redirect to /init

Put your data to rows and submit it

It will generate keys for your CA server

Remember your password!!! It will be used in work