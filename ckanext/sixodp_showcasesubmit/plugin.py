import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import six
from ckan.lib.plugins import DefaultTranslation
from ckanext.sixodp_showcasesubmit import helpers
from . import views


class Sixodp_ShowcasesubmitPlugin(plugins.SingletonPlugin, DefaultTranslation):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)
    if toolkit.check_ckan_version(min_version='2.5.0'):
        plugins.implements(plugins.ITranslation, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'sixodp_showcasesubmit')

    def update_config_schema(self, schema):
        ignore_missing = toolkit.get_validator('ignore_missing')

        schema.update({
            'ckanext.sixodp_showcasesubmit.recipient_emails': [ignore_missing, six.text_type],
        })

        return schema

    # IConfigurable

    def configure(self, config):
        # Raise an exception if required configs are missing
        required_keys = (
            'ckanext.sixodp_showcasesubmit.creating_user_username',
            'ckanext.sixodp_showcasesubmit.recaptcha_sitekey',
            'ckanext.sixodp_showcasesubmit.recaptcha_secret',
            'ckanext.sixodp_showcasesubmit.recipient_emails'
        )

        for key in required_keys:
            if config.get(key) is None:
                raise RuntimeError(
                    'Required configuration option {0} not found.'.format(
                        key
                    )
                )

    # ITemplateHelpers

    def get_helpers(self):
        return {'get_showcasesubmit_recaptcha_sitekey': helpers.get_showcasesubmit_recaptcha_sitekey}

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprint()
