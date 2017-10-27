from datetime import date
from validate import Validator
from configobj import ConfigObj
from subprocess import Popen, PIPE

import re
import os
import time
import string
import random
import pexpect


class CRT(object):
    def __init__(self):
        self.keyfile = ''
        self.csrfile = ''
        self.crtfile = ''
        self.p12file = ''
        self.p12pwd = ''
        self.p12pwdfile = ''
        self.commonname = ''
        self.validity = ''
        self.certtype = ''
        self.chainfile = ''

    def to_dict(self):
        return self.__dict__

    def from_dict(self, data):
        self.__dict__.update(data)


class CA(object):
    def __init__(self):
        self.name = ''
        self.dir = ''  # CA base directory
        self.database = ''
        self.certs = ''  # Used by openssl to store certificates, usually equal to new_certs_dir
        self.crl_dir = ''
        self.new_certs_dir = ''  # Used by openssl to store certificates, usually equal to certs dir
        self.certificate = ''
        self.private_key = ''
        self.certificatechain = ''
        self.configfile = ''
        self.certificateoutputpath = ''  # Proprietary output folder structured according to project needs
        self.use_smartcard = False
        self.smartcard_slot = ''
        self.chain_file = ''

    def to_dict(self):
        return self.__dict__

    def from_dict(self, data):
        self.__dict__.update(data)

    def sign_cert_request(self, csr, password):
        """
        input: instance of CSR class
        """

        # Prepare file structure
        certificateoutputpath = os.path.join(self.certificateoutputpath, csr.commonname)

        create_folder(certificateoutputpath)

        # Create certificate object
        crt = CRT()
        crt.keyfile = os.path.join(certificateoutputpath, csr.commonname + '.key')
        crt.csrfile = os.path.join(certificateoutputpath, csr.commonname + '.csr')
        crt.crtfile = os.path.join(certificateoutputpath, csr.commonname + '.crt')
        crt.p12file = os.path.join(certificateoutputpath, csr.commonname + '.p12')
        crt.p12pwdfile = os.path.join(certificateoutputpath, csr.commonname + '.pwd')
        crt.commonname = csr.commonname
        crt.validity = csr.validity
        crt.certtype = csr.certtype
        crt.chainfile = os.path.join(self.dir, self.chain_file)

        # Save key and csr for future reference
        write_to_file(crt.keyfile, csr.openssl_key)
        write_to_file(crt.csrfile, csr.openssl_csr)

        # Determine cmd for signing
        if csr.certtype == 'Client':
            extension = 'usr_cert'
            policy = 'policy_usr'
        elif csr.certtype == 'Server':
            extension = 'srv_cert'
            policy = 'policy_match'
        else:
            raise Exception("Invalid certificate type provided {certtype}".format(certtype=csr.certtype))

        # Default openssl cmd for signing csr
        cmd = 'openssl ca -config {configfile} ' \
              '-name {ca_name} ' \
              '-days {validity} ' \
              '-extensions {extension} ' \
              '-policy {policy} ' \
              '-passin pass:{password} ' \
              '-batch ' \
              '-out {outputfile} ' \
              '-infiles {infile}'.format(configfile=self.configfile,
                                         ca_name=self.name,
                                         validity=csr.validity,
                                         extension=extension,
                                         policy=policy,
                                         outputfile=crt.crtfile,
                                         infile=crt.csrfile,
                                         password=password)

        # Modified cmd for signing csr using smart card
        if self.use_smartcard:
                cmd = 'openssl ca -engine pkcs11 ' \
                      '-keyfile {smartcard_slot} ' \
                      '-keyform e ' \
                      '-config {configfile} ' \
                      '-name {ca_name} ' \
                      '-days {validity} ' \
                      '-extensions {extension} ' \
                      '-policy {policy} ' \
                      '-batch ' \
                      '-out {outputfile} ' \
                      '-infiles {infile}'.format(configfile=self.configfile,
                                                 ca_name=self.name,
                                                 validity=csr.validity,
                                                 extension=extension,
                                                 policy=policy,
                                                 outputfile=crt.crtfile,
                                                 infile=crt.csrfile,
                                                 smartcard_slot=self.smartcard_slot)

        # Sign certificate & return crt instance
        if self.use_smartcard:
            run_cmd_pexpect(cmd, (('PKCS#11 token PIN:', password),))
        else:
            run_cmd(cmd)

        audit_file = os.getcwd() + '/audit.log'
        write_to_file(audit_file, '{date_time} '
                                  'ca_name={ca_name} '
                                  'cn={cn} csr={csr} '
                                  'validity={validity} '
                                  'policy={policy}\n'.format(date_time=time.strftime("%d_%m_%Y-%H%M%S"),
                                                             ca_name=self.name,
                                                             cn=csr.commonname,
                                                             csr=csr.openssl_cfg_string.replace("\n", " "),
                                                             validity=csr.validity,
                                                             policy=policy), mode='append')
        return crt

    def revoke_cert(self, serial, password):
        certpath = os.path.join(self.dir, self.new_certs_dir, serial + '.pem')

        if self.use_smartcard:
            cmd = 'openssl ca -engine pkcs11 ' \
                  '-keyfile {smartcard_slot} ' \
                  '-keyform e ' \
                  '-config {configfile} ' \
                  '-name {ca_name} ' \
                  '-batch ' \
                  '-revoke {certpath}'.format(smartcard_slot=self.smartcard_slot,
                                              configfile=self.configfile,
                                              ca_name=self.name,
                                              certpath=certpath)

            run_cmd_pexpect(cmd, (('PKCS#11 token PIN:', password),))

        else:
            cmd = 'openssl ca -config {configfile} ' \
                  '-name {ca_name} ' \
                  '-passin pass:{password} ' \
                  '-batch ' \
                  '-revoke {certpath}'.format(configfile=self.configfile,
                                              ca_name=self.name,
                                              password=password,
                                              certpath=certpath)

            run_cmd(cmd)

    def generate_crl(self, password):
        crldir = os.path.join(self.dir, self.crl_dir)
        crlpemfile = os.path.join(crldir, 'crl.{date_time}.pem').format(date_time=time.strftime("%d_%m_%Y"))
        crltxtfile = os.path.join(crldir, 'crl.{date_time}.txt').format(date_time=time.strftime("%d_%m_%Y"))

        # Generate openssl CRL
        if self.use_smartcard:
            cmd = 'openssl ca -engine pkcs11 ' \
                  '-keyfile {smartcard_slot} ' \
                  '-keyform e ' \
                  '-config {configfile} ' \
                  '-name {ca_name} ' \
                  '-batch ' \
                  '-gencrl ' \
                  '-out {crlpemfile}'.format(smartcard_slot=self.smartcard_slot,
                                             configfile=self.configfile,
                                             ca_name=self.name,
                                             crlpemfile=crlpemfile)

            run_cmd_pexpect(cmd, (('PKCS#11 token PIN:', password),))

        else:
            cmd = 'openssl ca -config {configfile} ' \
                  '-name {ca_name} ' \
                  '-passin pass:{password} ' \
                  '-batch ' \
                  '-gencrl ' \
                  '-out {crlpemfile}'.format(configfile=self.configfile,
                                             ca_name=self.name,
                                             password=password,
                                             crlpemfile=crlpemfile)

            run_cmd(cmd)

        # Convert CRL to txt
        cmd = 'openssl crl ' \
              '-in {crlpemfile} ' \
              '-out {crltxtfile} ' \
              '-text'.format(crlpemfile=crlpemfile,
                             crltxtfile=crltxtfile)

        run_cmd(cmd)

        return crlpemfile, crltxtfile

    def list_db(self):
        dbpath = os.path.join(self.dir, self.database)
        dbfile = open(dbpath, "r")

        cert_list = []

        for line in dbfile:
            values = line.replace('\n', '').split('\t')

            status = values[0]
            expiration_date = convert_openssl_time(values[1])
            serial = values[3]
            commonname = values[5]

            cert_information = {'status': status,
                                'expiration_date': expiration_date,
                                'serial': serial,
                                'commonname': commonname}

            cert_list.append(cert_information)

        return cert_list


class CSR(object):
    def __init__(self):
        self.certtype = ''
        self.keylength = 0
        self.validity = 0
        self.country = ''
        self.state = ''
        self.locality = ''
        self.organisation = ''
        self.organisationalunit = ''
        self.commonname = ''
        self.email = ''
        self.openssl_cfg_string = ''
        self.openssl_key = ''
        self.openssl_csr = ''

    def to_dict(self):
        return self.__dict__

    def from_dict(self, data):
        self.__dict__.update(data)

    def _generate_openssl_cfg(self):
        # Prepare openssl config file for openssl_csr generation
        self.openssl_cfg_string = '[ req ]\n' \
                                  'default_bits = {keylength}\n' \
                                  'prompt = no\n' \
                                  'default_md = sha265\n' \
                                  'distinguished_name = dn\n'.format(keylength=self.keylength)

        if self.certtype == 'Server':
            # Add SAN attribute to certificate
            # in order to make this work add the following line to your openssl.cnf file in the InntermCA section:
            # copy_extensions = copy
            self.openssl_cfg_string += 'req_extensions = req_ext\n'\
                                       '[ req_ext ]\n' \
                                       'subjectKeyIdentifier = hash\n' \
                                       'basicConstraints = CA:FALSE\n' \
                                       'keyUsage = digitalSignature, keyEncipherment\n' \
                                       'subjectAltName = @alternate_names\n' \
                                       'nsComment = "OpenSSL Generated Certificate\n' \
                                       '[ alternate_names ]\n' \
                                       'DNS.1 = {commonname}\n'.format(commonname=self.commonname)

        self.openssl_cfg_string += '[ dn ]\n' \
                                  'CN = {commonname}\n' \
                                  'OU = {organisationalunit}\n' \
                                  'O = {organisation}\n' \
                                  'L = {locality}\n' \
                                  'ST = {state}\n' \
                                  'C = {country}\n'.format(commonname=self.commonname,
                                                           organisationalunit=self.organisationalunit,
                                                           organisation=self.organisation,
                                                           locality=self.locality,
                                                           state=self.state,
                                                           country=self.country)

        if self.certtype == 'Server':
            pass
        elif self.certtype == 'Client':
            self.openssl_cfg_string += 'emailAddress = {emailaddress}\n'.format(emailaddress=self.email)
        else:
            raise Exception('Invalid certificate type provided', self.certtype)

    def generate_openssl_csr(self):
        # Call generate_openssl_cfg to prepare the openssl configuration for this request by populating the
        # openssl_cfg_string var

        self._generate_openssl_cfg()

        # Generate openssl csr based on previously generated configuration and create new private key

        cmd = "openssl req -newkey rsa:2048 -keyout /dev/stdout -nodes -config /dev/stdin -out /dev/stdout -batch"
        output = run_cmd(cmd, input=self.openssl_cfg_string)
        self.openssl_key , self.openssl_csr = re.split('-----END PRIVATE KEY-----', output)
        self.openssl_key += '-----END PRIVATE KEY-----'


def convert_openssl_time(datetime):
    if len(datetime) == 13:
        year = int('20' + datetime[:2])
        month = int(datetime[2:4])
        day = int(datetime[4:6])
    elif len(datetime) == 15:
        year = int(datetime[:4])
        month = int(datetime[4:6])
        day = int(datetime[6:8])

    expiration_date = date(year, month, day)

    return expiration_date


def generate_p12(crt):
    # Generate password for p12 container
    password = generate_password(13)
    crt.p12pwd = password
    write_to_file(crt.p12pwdfile, crt.p12pwd)

    # run openssl command to generate p12 container
    cmd = "openssl pkcs12 " \
          "-export " \
          "-clcerts " \
          "-in {crtfile} " \
          "-inkey {keyfile} " \
          "-out {p12file} " \
          "-certfile {chainfile} " \
          "-passout pass:{password}" .format(crtfile=crt.crtfile,
                                             keyfile=crt.keyfile,
                                             p12file=crt.p12file,
                                             chainfile=crt.chainfile,
                                             password=crt.p12pwd)
    run_cmd(cmd)

    # return crt object
    return crt

def pki_init(dir_arg, passwd):
    run_cmd("./init-pki.sh " + dir_arg)
    cmd = "openssl genrsa -aes256 -out %s/ca.key -passout pass:%s 4096" %(dir_arg, passwd)
    run_cmd(cmd)

    cmd = "openssl req -new -x509 -days 3650 " \
          "-key {directory}/ca.key " \
          "-out {directory}/ca.crt " \
          "-config openssl-1.0.cnf " \
          "-passin pass:{password} -batch" .format(directory=dir_arg,
                                            password=passwd)
    args = "RU\n\n\nstepcart\n\n\nserv1\n"
    run_cmd(cmd)
    cmd = "cat %s/ca.crt > %s/ca_chain.crt" %(dir_arg,dir_arg)
    run_cmd(cmd)

def run_cmd(cmd, input=None):
    process = Popen(cmd.split(), shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate(input=input)

    if process.returncode:
        raise Exception(stderr, cmd)

    return stdout


def run_cmd_pexpect(cmd, output_input):
    child = pexpect.spawn(cmd)

    plog = file('pexpect.txt', 'w')
    child.logfile = plog

    for output, input in output_input:
        child.expect(output)
        child.sendline(input)

    output = child.readlines()
    child.close()

    if child.exitstatus:
        raise Exception(str(output), cmd)

    return child.before


def create_folder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def write_to_file(pathtofile, contents, mode='overwrite'):
    if mode == 'append':
        file = open(pathtofile, 'a')
    elif mode == 'overwrite':
        file = open(pathtofile, 'w')
    file.write(contents)
    file.close()


def generate_password(length):
    chars = string.ascii_letters + string.digits + '!@#$#*'
    random.seed = (os.urandom(1024))
    return ''.join(random.choice(chars) for i in range(length))


def opensslconfigfileparser(opensslconfigfile, canames):
    # Read configuration file
    opensslconfig = ConfigObj(opensslconfigfile)

    calist = []

    if opensslconfig:
        # Creating CA objects based on OpenSSL configuration file contents
        for caname in canames:
            c = CA()
            c.name = caname
            c.dir = opensslconfig[caname]['dir']
            c.database = opensslconfig[caname]['database'].strip('$dir').strip('/')
            c.certs = opensslconfig[caname]['certs'].strip('$dir').strip('/')
            c.crl_dir = opensslconfig[caname]['crl_dir'].strip('$dir').strip('/')
            c.new_certs_dir = opensslconfig[caname]['new_certs_dir'].strip('$dir').strip('/')
            c.certificate = opensslconfig[caname]['certificate'].strip('$dir').strip('/')
            c.private_key = opensslconfig[caname]['private_key'].strip('$dir').strip('/')
            c.configfile = opensslconfigfile
            c.certificateoutputpath = os.path.join(c.dir, c.new_certs_dir)

            # Some mojo here to avoid complicated solutions
            if opensslconfig[caname]['use_smartcard']:
                if opensslconfig[caname]['use_smartcard'] == 'True':
                    c.use_smartcard = True
                else:
                    c.use_smartcard = False
                c.smartcard_slot = opensslconfig[caname]['smartcard_slot']
                c.chain_file = opensslconfig[caname]['chain_file'].strip('$dir').strip('/')
            calist.append(c)

        # Obtaining default CSR settings from OpenSSL configuration file contents
        default_csr = CSR()
        default_csr.country = opensslconfig['req_distinguished_name']['countryName_default']
        default_csr.state = opensslconfig['req_distinguished_name']['stateOrProvinceName_default']
        default_csr.locality = opensslconfig['req_distinguished_name']['localityName_default']
        default_csr.organisation = opensslconfig['req_distinguished_name']['0.organizationName_default']
        default_csr.organisationalunit = opensslconfig['req_distinguished_name']['organizationalUnitName_default']

        return calist, default_csr
    else:
        raise Exception('Failed to read openssl config file', opensslconfigfile)


def generate_certificate(csr_data, calist, caname, password):
    # Generate CSR object based on provided request data
    csr = CSR()
    csr.from_dict(csr_data)

    # Generate openssl csr
    csr.generate_openssl_csr()

    # Select proper CA
    ca = [c for c in calist if c.name == caname][0]

    # Sign request
    crt = ca.sign_cert_request(csr, password)

    generate_p12(crt)
    return crt