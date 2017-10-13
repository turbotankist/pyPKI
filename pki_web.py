__author__ = 'turbotankist'

from datetime import date
from validate import Validator
from configobj import ConfigObj
from web.wsgiserver import CherryPyWSGIServer
from core.openssl_ca import run_cmd, run_cmd_pexpect, generate_password, opensslconfigfileparser, generate_certificate
from core.forms import config_form, usercert_form, servercert_form, bulkcert_form, revoke_form, report_form

import os
import re
import sys
import web
import time
import base64
import core.users

#===============================================================================
#  Init, things we cannot live without
#===============================================================================

# SSL
CherryPyWSGIServer.ssl_certificate = "pkiweb.crt"
CherryPyWSGIServer.ssl_private_key = "pkiweb.key"

# Declare URLs we will serve files for
urls = ('/', 'Home',
        '/home', 'Home',
        '/config', 'Config',
        '/generatecertificate', 'GenerateCertificate',
        '/clientcertificate', 'ClientCertificate',
        '/servercertificate', 'ServerCertificate',
        '/bulk', 'Bulk',
        '/revoke', 'Revoke',
        '/crl', 'Crl',
        '/report', 'Report',
        '/login', 'Login',
        '/progress', 'Progress')

render = web.template.render('templates/')
app = web.application(urls, globals())

BASE_PATH="/home/alexey/stepcart/alex/pypki/"
# Read configuration file
configfile = ConfigObj('config/pki.cfg', configspec='config/pkispec.cfg')

# Validate configuration file
validator = Validator()

valid = configfile.validate(validator)

# Exit in case of troubles
if not valid:
    raise Exception('Config file validation failed, exiting application', configfile, validator)
    sys.exit(1)

config = {'pkiroot': configfile['pkiroot'],
          'opensslconfigfile': configfile['opensslconfigfile'],
          'canames': configfile['canames'],
          'cwdir': os.getcwd(),
          'download_dir': './static'}

ca_list, defaultcsr = opensslconfigfileparser(config['opensslconfigfile'], config['canames'])

bulk_progress = 0
version = '1.1'
#===============================================================================
#  Functions required for the web interface to work
#===============================================================================


def create_zip(sources, destination, encrypt=False, password=''):
    sources = ' '.join(sources)

    if encrypt:
        cmd = 'zip -ejr {destination} {sources}'.format(sources=sources, destination=destination)
        run_cmd_pexpect(cmd, (('Enter password:', password), ('Verify password:', password)))
    else:
        cmd = 'zip -jr {destination} {sources}'.format(sources=sources, destination=destination)
        run_cmd(cmd)


def prepare_crt_for_download(crt_list):
    # Create list of all required p12, pwd and crt files to be included in the encrypted zip container
    zip_contents = []

    for crt in crt_list:
        zip_contents.append(crt.p12file)
        zip_contents.append(crt.p12pwdfile)
        zip_contents.append(crt.crtfile)

    # Create encrypted zip
    zipfile = os.path.join(config['download_dir'], 'crt_{date_time}.zip').format(date_time=time.strftime("%d_%m_%Y-%H%M%S"))
    password = generate_password(12)
    create_zip(zip_contents, zipfile, encrypt=True, password=password)

    return zipfile, password


def prepare_files_for_download(file_list):
    # Prepare file list for zip container
    zip_contents = []

    for file in file_list:
        zip_contents.append(file)

    # Create zip file
    zipfile = os.path.join(config['download_dir'], 'crl_{date_time}.zip').format(date_time=time.strftime("%d_%m_%Y-%H%M%S"))
    create_zip(zip_contents, zipfile)

    return zipfile


def report_certificates_to_expire(calist, caname, period):
    # Select proper ca object and request list of certificates
    ca = [c for c in calist if c.name == caname][0]
    cert_list = ca.list_db()

    expiration_list = []

    # Determine current date
    today = date.today()

    # Validate if certificate is valid and will expire within provided period
    for cert_information in cert_list:
        delta = cert_information['expiration_date'] - today

        if delta.days <= int(period) and cert_information['status'] == 'V':
            expiration_list.append(cert_information)

    return expiration_list


def csv_to_csr_data(csv, cert_type='Server'):
    csr_data_list = []

    # Split lines on newline character
    lines = csv.split('\n')

    # Treat each line and create the csr_data
    for line in lines:
        values = line.split(',')

        if cert_type == 'Server':
            csr_data = {'certtype': cert_type,
                        'commonname': values[0],
                        'validity': values[1],
                        'country': defaultcsr.country,
                        'state': defaultcsr.state,
                        'locality': defaultcsr.locality,
                        'organisation': defaultcsr.organisation,
                        'organisationalunit': defaultcsr.organisationalunit}

        else:
            csr_data = {'certtype': cert_type,
                        'country': values[0],
                        'state': values[1],
                        'locality': values[2],
                        'organisation': values[3],
                        'organisationalunit': values[4],
                        'commonname': values[5],
                        'email': values[6],
                        'validity': values[7] or 365}

        csr_data_list.append(csr_data)

    return csr_data_list


def authentication():
    if web.ctx.path != '/login':
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            pass

        else:
            raise web.seeother('/login')


#===============================================================================
#  Web interface URI's
#===============================================================================


class Login(object):
    def GET(self):
        auth = web.ctx.env.get('HTTP_AUTHORIZATION')
        authreq = False
        if auth is None:
            authreq = True
        else:
            auth = re.sub('^Basic ', '', auth)
            username,password = base64.decodestring(auth).split(':')
            if (username, password) in core.users.allowed:
                raise web.seeother('/home')
            else:
                authreq = True
        if authreq:
            web.header('WWW-Authenticate','Basic realm="PKIweb authentication"')
            web.ctx.status = '401 Unauthorized'
            return


class Home(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            return render.home(version)

        else:
            raise web.seeother('/login')


class Config(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = config_form()

            # Set current values on form
            form.pkiroot.value = config['pkiroot']
            form.opensslconfigfile.value = config['opensslconfigfile']
            form.canames.value = ','.join(config['canames'])

            return render.configuration(form, version)

        else:
            raise web.seeother('/login')

    def POST(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = config_form()

            if not form.validates():
                return render.configuration(form, version)

            # Update configuration
            config['pkiroot'] = configfile['pkiroot'] = form.pkiroot.value
            config['opensslconfigfile'] = configfile['opensslconfigfile'] = form.opensslconfigfile.value
            config['canames'] = configfile['canames'] = form.canames.value.split(',')

            # Write configuration to disk
            configfile.write()

            return render.configuration(form, version)

        else:
            raise web.seeother('/login')


class GenerateCertificate(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            return render.generatecertificate(version)

        else:
            raise web.seeother('/login')


class ClientCertificate(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = usercert_form()

            # Set values based on default CSR
            form.selected_ca.args = [ca.name for ca in ca_list]
            form.country.value = defaultcsr.country
            form.state.value = defaultcsr.state
            form.locality.value = defaultcsr.locality
            form.organisation.value = defaultcsr.organisation
            form.organisationalunit.value = defaultcsr.organisationalunit
            form.validity.value = 365

            return render.form(form)

        else:
            raise web.seeother('/login')

    def POST(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = usercert_form()
            data = web.input()

            if not form.validates():
                # Set values based on default CSR
                form.selected_ca.args = [ca.name for ca in ca_list]
                form.country.value = defaultcsr.country
                form.state.value = defaultcsr.state
                form.locality.value = defaultcsr.locality
                form.organisation.value = defaultcsr.organisation
                form.organisationalunit.value = defaultcsr.organisationalunit
                form.validity.value = 365

                return render.generatecertificate_err(form, version)

            # Prepare csr data based on form input
            csr_data = {'certtype': data['certtype'],
                        'keylength': 2048,
                        'validity': data['validity'],
                        'country': data['country'],
                        'state': data['state'],
                        'locality': data['locality'],
                        'organisation': data['organisation'],
                        'organisationalunit': data['organisationalunit'],
                        'commonname': data['commonname'],
                        'email': data['email']}

            try:
                # Generate certificate based on CSR
                crt = generate_certificate(csr_data, ca_list, data['selected_ca'], data['password'])
            except Exception as e:
                return render.error(e, version)

            # Prepare certificate for download
            crt_list = [crt, ]
            zipfile, password = prepare_crt_for_download(crt_list)

            return render.download(crt_list, zipfile, password, version)

        else:
            raise web.seeother('/login')


class ServerCertificate(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = servercert_form()

            # Set values based on default CSR
            form.selected_ca.args = [ca.name for ca in ca_list]
            form.country.value = defaultcsr.country
            form.state.value = defaultcsr.state
            form.locality.value = defaultcsr.locality
            form.organisation.value = defaultcsr.organisation
            form.organisationalunit.value = defaultcsr.organisationalunit
            form.validity.value = 365

            return render.form(form)

        else:
            raise web.seeother('/login')

    def POST(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = servercert_form()
            data = web.input()

            if not form.validates():
                # Set values based on default CSR
                form.selected_ca.args = [ca.name for ca in ca_list]
                form.country.value = defaultcsr.country
                form.state.value = defaultcsr.state
                form.locality.value = defaultcsr.locality
                form.organisation.value = defaultcsr.organisation
                form.organisationalunit.value = defaultcsr.organisationalunit
                form.validity.value = 365

                return render.generatecertificate_err(form, version)

            # Prepare csr data based on form input
            csr_data = {'certtype': data['certtype'],
                        'keylength': 2048,
                        'validity': data['validity'],
                        'country': data['country'],
                        'state': data['state'],
                        'locality': data['locality'],
                        'organisation': data['organisation'],
                        'organisationalunit': data['organisationalunit'],
                        'commonname': data['commonname']}

            try:
                # Generate certificate based on CSR
                crt = generate_certificate(csr_data, ca_list, data['selected_ca'], data['password'])
            except Exception as e:
                return render.error(e, version)

            # Prepare certificate for download
            crt_list = [crt, ]
            zipfile, password = prepare_crt_for_download(crt_list)

            return render.download(crt_list, zipfile, password, version)

        else:
            raise web.seeother('/login')


class Bulk(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            form = bulkcert_form()

            # Set values of CA's
            form.selected_ca.args = [ca.name for ca in ca_list]

            return render.form(form)

        else:
            raise web.seeother('/login')

    def POST(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            global bulk_progress
            form = bulkcert_form()
            data = web.input()

            if not form.validates():
                # Set values of CA's
                form.selected_ca.args = [ca.name for ca in ca_list]

                return render.generatecertificate_err(form, version)

            csr_data_list = csv_to_csr_data(data['req_list'], cert_type=data['certtype'])

            crt_list = []

            for csr_data in csr_data_list:
                try:
                    crt = generate_certificate(csr_data, ca_list, data['selected_ca'], data['password'])

                    bulk_progress += 100/len(csr_data_list)

                except Exception as e:
                    return render.error(e, version)

                crt_list.append(crt)

            zipfile, password = prepare_crt_for_download(crt_list)

            bulk_progress = 0

            return render.download(crt_list, zipfile, password, version)

        else:
            raise web.seeother('/login')


class Revoke(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            if not web.input():
                # Initial request
                form = revoke_form()
                form.selected_ca.args = ['', ] + [ca.name for ca in ca_list]

                return render.revoke(form, version)

            if web.input()['request'] == 'getlist':
                ca = [c for c in ca_list if c.name == web.input()['ca']][0]
                cert_list = ca.list_db()
                rev_list = [cert for cert in cert_list if cert['status'] == 'V']
                return render.revoke_list(rev_list)

        else:
            raise web.seeother('/login')

    def POST(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:

            data = web.input()
            form = revoke_form()

            if not form.validates():
                form.selected_ca.args = ['', ] + [ca.name for ca in ca_list]
                return render.revoke(form, version)

            # Decide on CA
            ca = [c for c in ca_list if c.name == web.input()['selected_ca']][0]

            for key, value in data.iteritems():
                if value == 'R':
                    try:
                        ca.revoke_cert(key, data['password'])
                    except Exception as e:
                        return render.error(e, version)

            form = revoke_form()
            form.selected_ca.args = ['', ] + [ca.name for ca in ca_list]
            return render.revoke(form, version)

        else:
            raise web.seeother('/login')


class Crl(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            # Decide on CA to generate CRL for
            ca = [c for c in ca_list if c.name == web.input()['ca']][0]

            # Generate CRL and get output
            try:
                crl_pem, crl_txt = ca.generate_crl(web.input()['password'])
            except Exception as e:
                return render.error(e, version)

            # Prepare zip file for download
            file_list = (crl_pem, crl_txt)
            crl = prepare_files_for_download(file_list)

            # Serve zip file for download
            web.redirect(crl)

        else:
            raise web.seeother('/login')


class Report(object):
    def GET(self):
        if web.ctx.env.get('HTTP_AUTHORIZATION') is not None:
            if not web.input():
                # Initial request
                form = report_form()
                form.selected_ca.args = ['', ] + [ca.name for ca in ca_list]

                return render.report(form, version)

            if web.input()['request'] == 'getlist':
                report = report_certificates_to_expire(ca_list, web.input()['ca'], web.input()['period'])
                return render.report_list(report)

        else:
            raise web.seeother('/login')


class Progress(object):
    def GET(self):
        if web.input():
            return bulk_progress

#===============================================================================
#  Main
#===============================================================================


def main():
    web.config.debug = True
    # Start the web application
    web.internalerror = web.debugerror
    app.add_processor(web.loadhook(authentication))
    app.run()

if __name__ == '__main__':
    main()