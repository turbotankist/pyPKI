__author__ = 'dennisverslegers'

from web import form

import web.utils, web.net

#===============================================================================
#  Modified web.form class required to correctly display bootstrap based forms
#===============================================================================
'''
<div class="control-group">
            <label class="control-label" for="input01">Text input</label>
            <div class="controls">
              <input type="text" class="input-xlarge" id="input01">
              <p class="help-block">In addition to freeform text, any HTML5 text-based input appears like so.</p>
            </div>
          </div>
- See more at: http://www.w3resource.com/twitter-bootstrap/forms-tutorial.php#sthash.qVYIt6Uv.dpuf
'''


class BootstrapFormTable(form.Form):
    def rendernote(self, note):
        if note:
            return '<p class="help-block warning">%s</p>' % web.net.websafe(note)
        else:
            return ""

    def render(self):
        out = ''
        out += self.rendernote(self.note)

        for i in self.inputs:
            html = web.utils.safeunicode(i.pre) + i.render() + self.rendernote(i.note) + web.utils.safeunicode(i.post)
            if i.is_hidden():
                out += '    <tr style="display: none;"><th></th><td>%s</td></tr>\n' % (html)
            else:
                out += '<div class="form-group">\n' \
                       '<label class="col-sm-2 control-label" for="%s">%s</label>\n' \
                       '<div class="col-sm-10">\n' \
                       '%s\n' \
                       '</div>\n' \
                       '</div>' % (i.id, web.net.websafe(i.description), html)

        out += '</div>'
        return out


class BootstrapFormInline(form.Form):
    def rendernote(self, note):
        if note:
            return '<p class="help-block warning">%s</p>' % web.net.websafe(note)
        else:
            return ""

    def render(self):
        out = ''
        out += self.rendernote(self.note)

        for i in self.inputs:
            html = web.utils.safeunicode(i.pre) + i.render() + self.rendernote(i.note) + web.utils.safeunicode(i.post)
            if i.is_hidden():
                out += '    <tr style="display: none;"><th></th><td>%s</td></tr>\n' % (html)
            else:
                out += '<label class="control-label" for="%s">%s</label>%s' % (i.id, web.net.websafe(i.description), html)
        return out

#===============================================================================
#  Form definitions
#===============================================================================

config_form = BootstrapFormTable(
    form.Textbox('pkiroot',
                 form.notnull,
                 #form.regexp('([\w\w])', 'Please provide a valid country code'),
                 class_='form-control input-sm',
                 type='text',
                 description='PKI root directory'),
    form.Textbox('opensslconfigfile',
                 form.notnull,
                 class_='form-control input-sm',
                 type='text',
                 description='OpenSSL configuration file'),
    form.Textbox('canames',
                 form.notnull,
                 class_='form-control input-sm',
                 type='text',
                 description='Names of CA sections')
)

usercert_form = BootstrapFormTable(
    form.Dropdown('selected_ca',
                  [('value1', 'description1'), ('value2', 'description2')],
                  class_='form-control input-sm',
                  description='Select CA'),
    form.Textbox('country',
                 form.notnull,
                 form.regexp('([\w\w])', 'Please provide a valid country code'),
                 type='text',
                 class_='form-control input-sm',
                 description='Country'),
    form.Textbox('state',
                 form.notnull,
                 class_='form-control input-sm',
                 description='State'),
    form.Textbox('locality',
                 form.notnull,
                 class_='form-control input-sm',
                 description='City'),
    form.Textbox('organisation',
                 form.notnull,
                 type="readonly",
                 class_='form-control input-sm',
                 description='Organisation'),
    form.Textbox('organisationalunit',
                 form.notnull,
                 class_='form-control input-sm',
                 description='Organisational Unit'),
    form.Textbox('validity',
                 form.notnull,
                 form.regexp('([\d+])', 'Please provide a valid duration'),
                 class_='form-control input-sm',
                 description='Validity period'),
    form.Textbox('commonname',
                 form.notnull,
                 type='text',
                 class_='form-control input-sm',
                 description='Common Name'),
    form.Textbox('email',
                 form.notnull,
                 class_='form-control input-sm',
                 description='E-mail'),
    form.Password('password',
                  form.notnull,
                  class_='form-control input-sm',
                  description='Password'),
    form.Hidden('certtype',
                type='readonly',
                class_='form-control input-sm',
                value='Client'),
    form.Hidden('mode',
                type='readonly',
                class_='form-control input-sm',
                value='manual')
)

servercert_form = BootstrapFormTable(
    form.Dropdown('selected_ca',
                  [('value1', 'description1'), ('value2', 'description2')],
                  class_='form-control input-sm',
                  description='Select CA'),
    form.Textbox('validity',
                 form.notnull,
                 form.regexp('([\d+])', 'Please provide a valid duration'),
                 class_='form-control input-sm',
                 description='Validity period',
                 value=365),
    form.Textbox('commonname',
                 form.notnull,
                 form.regexp('([a-z A-Z])', 'Common name can only contain letters and spaces'),
                 class_='form-control input-sm',
                 description='Common Name',
                 value='certificate_common_name'),
    form.Password('password',
                  form.notnull,
                  class_='form-control input-sm',
                  description='Password'),
    form.Hidden('country',
                type='text',
                class_='form-control input-sm',
                description='Country'),
    form.Hidden('state',
                form.notnull,
                class_='form-control input-sm',
                description='State'),
    form.Hidden('locality',
                form.notnull,
                class_='form-control input-sm',
                description='City'),
    form.Hidden('organisation',
                form.notnull,
                type="readonly",
                class_='form-control input-sm',
                description='Organisation'),
    form.Hidden('organisationalunit',
                form.notnull,
                class_='form-control input-sm',
                description='Organisational Unit'),
    form.Hidden('certtype',
                type='readonly',
                class_='form-control input-sm',
                value='Server'),
    form.Hidden('mode',
                type='readonly',
                class_='form-control input-sm',
                value='manual')
)

bulkcert_form = BootstrapFormTable(
    form.Dropdown('selected_ca',
                  [('value1', 'description1'), ('value2', 'description2')],
                  class_='form-control input-sm input-sm',
                  description='Select CA'),
    form.Dropdown('certtype',
                  ['Select', 'Client', 'Server'],
                  class_='form-control input-sm input-sm',
                  description='Select Certificate Type'),
    form.Password('password',
                  form.notnull,
                  class_='form-control input-sm input-sm',
                  description='Password'),
    form.File('req_list',
              type='file',
              class_='form-control input-sm input-sm',
              description='Bulk request file'),
    form.Hidden('mode',
                type='readonly',
                class_='form-control input-sm',
                value='bulk')
)

revoke_form = BootstrapFormInline(
    form.Dropdown('selected_ca',
                  [('value1', 'description1'), ('value2', 'description2')],
                  class_='form-control input-sm',
                  onchange='getList(this.value)',
                  description='Select CA'),
    form.Password('password',
                  form.notnull,
                  class_='form-control input-sm',
                  description='Password')
)

report_form = BootstrapFormInline(
    form.Dropdown('selected_ca',
                  [('value1', 'description1'), ('value2', 'description2')],
                  class_='form-control input-sm',
                  description='Select CA'),
    form.Textbox('period',
                 form.regexp('([\d+])', 'Please provide a valid duration'),
                 class_='form-control input-sm',
                 description='Timeframe to check',
                 value='365'),
)