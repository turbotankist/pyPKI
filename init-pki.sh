#!/bin/bash

DIR=$1

if [ -d "$DIR" ]; then
rm -rf "${DIR}"
fi
mkdir "${DIR}"
mkdir "${DIR}"/ca.db.tmp
mkdir "${DIR}"/ca.db.certs
mkdir "${DIR}"/ca.db.crl
echo 01 > "${DIR}"/ca.db.serial
echo 01 > "${DIR}"/ca.db.crlserial
touch "${DIR}"/ca.db.index
openssl rand -out "${DIR}"/ca.db.rand 8192


# openssl genrsa -aes256 -out "${DIR}"/RootCA.key -passout pass:${passwd} 4096
# openssl req -new -x509 -days 3650 -key "${DIR}"/ca.key -out "${DIR}"/ca.crt -config openssl-1.0.cnf

