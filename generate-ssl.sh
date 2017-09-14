#!/bin/bash

mkdir ca
mkdir ca/ca.db.tmp
mkdir ca/ca.db.certs
mkdir ca/ca.db.crl
echo 01 > ca/ca.db.serial
echo 01 > ca/ca.db.crlserial
touch ca/ca.db.index
openssl rand -out ca/ca.db.rand 8192

cat > openssl.cnf <<__EOF__
[ ca ]
default_ca  = CA        # The default ca section

[ CA ]
dir     = ./ca         
# Where everything is kept
certs       = $dir/ca.db.certs      
# Where the issued certs are kept
crl_dir = $dir/ca.db.crl         
# Where the issued crl are kept
database    = $dir/ca.db.index     
# database index file.
unique_subject = no           
# Set to 'no' to allow creation of several ctificates with same subject.
new_certs_dir   = $dir/ca.db.certs 
# default place for new certs.
certificate = $dir/ca.crt   
# The CA certificate
serial      = $dir/ca.db.serial     
# The current serial number
crlnumber   = $dir/ca.db.crlserial  
# the current crl number must be commented out to leave a V1 CRL
private_key = $dir/ca.key             
# The private key
RANDFILE    = $dir/ca.db.rand        
# private random number file
name_opt    = ca_default        
# Subject Name options
cert_opt    = ca_default        
# Certificate field options

default_days    = 365           
# how long to certify for
default_crl_days  = 60          
# how long before next CRL
default_md  = md5       
# use public key default MD
preserve    = no            
# keep passed DN ordering

policy          = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = optional
localityName            = optional 
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_usr ]
countryName     = supplied
stateOrProvinceName = optional
localityName        = optional
organizationName    = supplied
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = supplied

[ req ]
default_bits        = 2048
default_keyfile     = privkey.pem
distinguished_name  = req_distinguished_name
attributes      = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert
string_mask = nombstr

[ req_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default     = RU
countryName_min         = 2
countryName_max         = 2

stateOrProvinceName     = State or Province Name (full name)
stateOrProvinceName_default = 

localityName            = Locality Name (eg, city)
localityName_default        = Moscow

0.organizationName      = Organization Name (eg, company)
0.organizationName_default  = Company

1.organizationName      = Second Organization Name (eg, company)
1.organizationName_default  = not used

organizationalUnitName      = Organizational Unit Name (eg, section)
organizationalUnitName_default  = CA project

commonName          = Common Name (eg, YOUR name)
commonName_max          = 64

emailAddress            = Email Address
emailAddress_max        = 64

[ req_attributes ]
# challengePassword     = A challenge password
# challengePassword_min     = 4
# challengePassword_max     = 20

# unstructuredName      = An optional company name

[ srv_cert ]
basicConstraints=CA:FALSE
nsCertType            = server
crlDistributionPoints = URI:http://openca.stepcart.com/crl.pem
nsComment           = "OpenSSL Generated Server Certificate"

[ usr_cert ]
basicConstraints=CA:FALSE
nsCertType = client, email
nsComment           = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]
# Extensions for a typical CA
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true

[ crl_ext ]
# CRL extensions.
authorityKeyIdentifier=keyid:always,issuer:always

## Establishing our CA’s
### Setup Root CA
__EOF__

mkdir RootCA

openssl genrsa -des3 -out ./RootCA/RootCA.key 2048
openssl req -new -x509 -days 3650 -key ./RootCA/RootCA.key -out ./RootCA/RootCA.crt -config openssl.cnf
