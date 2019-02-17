import json
import sys
from omeroweb.settings import process_custom_settings, report_settings


def str_not_empty(o):
    s = str(o)
    if not o or not s:
        raise ValueError('Invalid empty value')
    return s


def str_or_none(o):
    if o is not None:
        o = str(o)
    return o


# authorization: https://github.com/login/oauth/authorize
# token: https://github.com/login/oauth/access_token
# userinfo: https://api.github.com/user

# load settings
OAUTH_SETTINGS_MAPPING = {
    'omero.web.oauth.client.name':
        ['OAUTH_CLIENT_NAME', 'OAuth Client', str, None],
    'omero.web.oauth.client.id':
        ['OAUTH_CLIENT_ID', None, str_or_none, None],
    'omero.web.oauth.client.secret':
        ['OAUTH_CLIENT_SECRET', None, str_or_none, None],
    'omero.web.oauth.client.scope':
        ['OAUTH_CLIENT_SCOPE', '[]', json.loads, None],
    'omero.web.oauth.client.callbackurl':
        ['OAUTH_CALLBACK_URL', None, str_or_none, None],

    'omero.web.oauth.url.authorization':
        ['OAUTH_URL_AUTHORIZATION', '', str_not_empty, None],
    'omero.web.oauth.url.token':
        ['OAUTH_URL_TOKEN', '', str_not_empty, None],
    'omero.web.oauth.url.userinfo':
        ['OAUTH_URL_USERINFO', '', str_not_empty, None],
    'omero.web.oauth.userinfo.type':
        ['OAUTH_USERINFO_TYPE', 'default', str_not_empty, None],

    'omero.web.oauth.host':
        ['OAUTH_HOST', '', str_not_empty, None],
    'omero.web.oauth.port':
        ['OAUTH_PORT', 4064, int, None],
    'omero.web.oauth.admin.user':
        ['OAUTH_ADMIN_USERNAME', '', str_not_empty, None],
    'omero.web.oauth.admin.password':
        ['OAUTH_ADMIN_PASSWORD', '', str_not_empty, None],

    # {templates} are expanded using fields in userinfo
    # These may be ignored if omero.web.oauth.userinfo.type is not default
    'omero.web.oauth.user.name':
        ['OAUTH_USER_NAME', 'oauth-{login}', str_not_empty, None],
    'omero.web.oauth.user.email':
        ['OAUTH_USER_EMAIL', '{email}', str, None],
    'omero.web.oauth.user.firstname':
        ['OAUTH_USER_FIRSTNAME', 'oauth', str_not_empty, None],
    'omero.web.oauth.user.lastname':
        ['OAUTH_USER_LASTNAME', '{login}', str_not_empty, None],

    'omero.web.oauth.user.timeout':
        ['OAUTH_USER_TIMEOUT', 86400, int, None],

    'omero.web.oauth.group.name':
        ['OAUTH_GROUP_NAME', '', str_not_empty, None],
    'omero.web.oauth.group.templatetime':
        ['OAUTH_GROUP_NAME_TEMPLATETIME', False, bool, None],
    'omero.web.oauth.group.perms':
        ['OAUTH_GROUP_PERMS', 'rw----', str_not_empty, None],

    'omero.web.oauth.sessiontoken.enable':
        ['OAUTH_SESSIONTOKEN_ENABLE', False, bool, None],
}


process_custom_settings(sys.modules[__name__], 'OAUTH_SETTINGS_MAPPING')
report_settings(sys.modules[__name__])
