from ckan.plugins import toolkit


def get_showcasesubmit_recaptcha_sitekey():
    return toolkit.config.get('ckanext.sixodp_showcasesubmit.recaptcha_sitekey')
