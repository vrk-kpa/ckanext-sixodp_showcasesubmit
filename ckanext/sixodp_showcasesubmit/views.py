from flask import Blueprint
from flask.views import MethodView
from ckan.plugins import toolkit
from ckan import model
from ckan.lib.mailer import MailerException
import json
import urllib
import re
import logging
import http

log = logging.getLogger(__name__)

showcasesubmit = Blueprint('showcasesubmit', __name__)


def get_blueprint():
    return [showcasesubmit]

def index_template():
    return 'sixodp_showcasesubmit/base_form_page.html'


def validateReCaptcha(recaptcha_response):
    response_data_dict = {}
    try:
        connection = http.client.HTTPSConnection('google.com')
        params = urllib.parse.urlencode({
            'secret': toolkit.config.get('ckanext.sixodp_showcasesubmit.recaptcha_secret'),
            'response': recaptcha_response,
            'remoteip': toolkit.request.environ.get('REMOTE_ADDR')
        })
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'text/plain'}
        connection.request('POST', '/recaptcha/api/siteverify', params, headers)
        response_data_dict = json.loads(connection.getresponse().read())
        connection.close()

        if response_data_dict.get('success') is not True:
            raise toolkit.ValidationError('Google reCaptcha validation failed')
    except Exception:
        log.error('Connection to Google reCaptcha API failed')
        raise toolkit.ValidationError('Connection to Google reCaptcha API failed, unable to validate captcha')


def sendNewShowcaseNotifications(showcase_name):
    recipient_emails = toolkit.config.get('ckanext.sixodp_showcasesubmit.recipient_emails').split(' ')
    showcase_url = toolkit.url_for('sixodp_showcase.read', id=showcase_name, qualified=True)

    message_body = toolkit._('A user has submitted a new showcase') + ': ' + showcase_url

    try:
        for email in recipient_emails:
            toolkit.mail_recipient("", email, toolkit._('New showcase notification'), message_body)
    except MailerException as e:
        toolkit.h.flash_error(toolkit._("Failed to send email notification"))
        log.error('Error sending email: %s', e)


class ShowcaseSubmitView(MethodView):
    def get(self):
        vars = {'data': {}, 'errors': {},
                'error_summary': {}, 'message': None,
                'dataset_type': 'showcase'}
        return toolkit.render(index_template(), extra_vars=vars)

    def post(self):
        try:
            data, errors, error_summary, message = self._submit()

            vars = {'data': data, 'errors': errors,
                    'error_summary': error_summary, 'message': message,
                    'dataset_type': 'showcase'}
            return toolkit.render(index_template(), extra_vars=vars)
        except:
            import traceback
            traceback.print_exc()
            raise

    def _submit(self):
        try:
            username = toolkit.config.get('ckanext.sixodp_showcasesubmit.creating_user_username')
            user = model.User.get(username)

            if not user:
                toolkit.abort(403, toolkit._('There is a misconfiguration in the service, please contact admins.'))

            context = {'model': model, 'session': model.Session,
                       'user': user.id, 'auth_user_obj': user,
                       'save': 'save' in toolkit.request.form}

            data_dict = dict(toolkit.request.form)
            #data_dict = clean_dict(dict_fns.unflatten(
                #tuplize_dict(parse_params(request.POST))))

            data_dict['title_translated'] = {'fi': data_dict.get('title')}
            data_dict['type'] = 'showcase'
            data_dict['name'] = re.sub('[^a-z0-9]+', '', data_dict.get('title'))
            data_dict['featured'] = False
            data_dict['archived'] = False
            data_dict['private'] = True
            data_dict['keywords'] = {
                'fi': ['Ilmoitetut'],
                'en': [],
                'sv': []
            }

            validateReCaptcha(data_dict.get('g-recaptcha-response'))

            new_showcase = toolkit.get_action('ckanext_showcase_create')(context, data_dict)

            if data_dict.get('datasets'):
                datasets_to_link = data_dict.get('datasets').split(',')

                for package_name in datasets_to_link:
                    association_dict = {"showcase_id": new_showcase.get('id'),
                                        "package_id": package_name}
                    try:
                        toolkit.get_action('ckanext_showcase_package_association_create')(
                            context, association_dict)
                    except Exception:
                        new_showcase['notes_translated']['fi'] = \
                            new_showcase.get('notes_translated', {'fi': ''}).get('fi', '') + '\n\n' + toolkit._(
                                'N.B. The following dataset could not be automatically linked') + ': ' + package_name
                        toolkit.get_action('ckanext_showcase_update')(context, new_showcase)

        except toolkit.NotAuthorized:
            toolkit.abort(403, toolkit._('Unauthorized to create a package'))
        except toolkit.ValidationError as e:
            import traceback
            traceback.print_exc()
            errors = e.error_dict
            error_summary = e.error_summary
            data_dict['state'] = 'none'
            return data_dict, errors, error_summary, None

        sendNewShowcaseNotifications(data_dict.get('name'))

        return {}, {}, {}, {'class': 'success', 'text': toolkit._('Showcase submitted successfully')}

    def ajax_submit(self):
        data, errors, error_summary, message = _submit()
        data = flatten_to_string_key({'data': data, 'errors': errors, 'error_summary': error_summary, 'message': message})
        response.headers['Content-Type'] = 'application/json;charset=utf-8'
        return json.dumps(data)


showcasesubmit.add_url_rule('/submit-showcase', view_func=ShowcaseSubmitView.as_view('submit'))
