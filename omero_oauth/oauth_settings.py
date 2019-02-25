import json
import re
import sys
import yaml
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


# https://github.com/jupyterhub/zero-to-jupyterhub-k8s/blob/0.8.0/images/hub/z2jh.py#L33-L47
def _merge_dictionaries(a, b):
    merged = a.copy()
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merged[key] = _merge_dictionaries(a[key], b[key])
            else:
                merged[key] = b[key]
        else:
            merged[key] = b[key]
    return merged


def json_oauth_str_or_files(o):
    """
    :param o: either:
        - A JSON object containing the full OAuth provider configuration
        - A JSON list files in JSON or YAML format containing a dictionary
          that will be merged
    """
    dict_or_list = json.loads(o)
    if isinstance(dict_or_list, list):
        cfg = {}
        for cfgfile in dict_or_list:
            with open(cfgfile) as f:
                if cfgfile.endswith('.yml') or cfgfile.endswith('.yaml'):
                    d = yaml.load(f)
                else:
                    d = json.load(f)
            cfg = _merge_dictionaries(cfg, d)
    else:
        cfg = json.loads(o)
    for key in cfg:
        if not re.match('[a-z][a-z0-9]+$', key):
            raise ValueError('Invalid section name: {}'.format(key))
    return cfg


# load settings
OAUTH_SETTINGS_MAPPING = {
    'omero.web.oauth.providers':
        ['OAUTH_PROVIDERS', '{}', json_oauth_str_or_files, None],

    'omero.web.oauth.display.name':
        ['OAUTH_DISPLAY_NAME', 'OAuth Client', str, None],
    # 'omero.web.oauth.baseurl':
    #     ['OAUTH_BASEURL', None, str_not_empty, None],

    'omero.web.oauth.host':
        ['OAUTH_HOST', '', str_not_empty, None],
    'omero.web.oauth.port':
        ['OAUTH_PORT', 4064, int, None],
    'omero.web.oauth.admin.user':
        ['OAUTH_ADMIN_USERNAME', '', str_not_empty, None],
    'omero.web.oauth.admin.password':
        ['OAUTH_ADMIN_PASSWORD', '', str_not_empty, None],

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
