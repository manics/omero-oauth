.. image:: https://travis-ci.org/openmicroscopy/omero-signup.svg?branch=master
    :target: https://travis-ci.org/openmicroscopy/omero-webtest


OMERO.oauth
===========
OMERO.web app to allow OAuth2 login to OMERO.


Requirements
------------

* OMERO.web 5.4 or newer.


Installation
------------

This section assumes that an OMERO.web is already installed.

::

    $ python setup.py install
    $ omero config append omero.web.apps '"omero_signup"'

OMERO.web 5.4.* contains a bug that prevents login using this app.
You will need to apply `the patch omeroweb-5.4.10-webgateway-marshal-py.patch <omeroweb-5.4.10-webgateway-marshal-py.patch>`_ to your copy of OMERO.web:

::

    $ cd OMERO.py-5.4.10-ice36-b105
    $ patch -p1 < ../omeroweb-5.4.10-webgateway-marshal-py.patch

This bug is fixed in 5.5.0: https://github.com/openmicroscopy/openmicroscopy/pull/5890


Configuration settings:

- ``omero.web.oauth.client.name``: Name of the login provider, displayed on the login page, default ``'OAuth Client``
- ``omero.web.oauth.client.id``: Client ID, obtain this from your OAuth provider
- ``omero.web.oauth.client.secret``: Client secret ID, provided by most OAuth providers, optional
- ``omero.web.oauth.client.scope``: A provider dependent list of scopes, optional

- ``omero.web.oauth.url.authorization``: OAuth2 authorisation URL
- ``omero.web.oauth.url.token``: OAuth2 authorisation URL
- ``omero.web.oauth.url.userinfo``: OAuth user information URL

- ``omero.web.oauth.host``: OMERO.server hostname
- ``omero.web.oauth.port``: OMERO.server port, optional, defualt ``4064``
- ``omero.web.oauth.admin.user``: OMERO admin username, must have permission to create groups, users, and user sessions using sudo
- ``omero.web.oauth.admin.password``: Password for OMERO admin username

The next 4 properties contain ``{template}`` variables which will be filled using the fields in the JSON response from. ``omero.web.oauth.url.userinfo``.
Any field in the response can be used in a template:

- ``omero.web.oauth.user.name``: OMERO username template, default ``oauth-{login}``. If you have other accounts on the system you must ensure accounts matching this template correspond to the OAuth user
- ``omero.web.oauth.user.email``: OMERO Email, default ``{email}``', str, None],``
- ``omero.web.oauth.user.firstname``: OMERO firstname, default ``oauth``
- ``omero.web.oauth.user.lastname``: OMERO lastname, default ``{login}``

- ``omero.web.oauth.user.timeout``: Maximum session length in seconds, default ``86400``

- ``omero.web.oauth.group.name``: Default group for new users, will be created if it doesn't exist
- ``omero.web.oauth.group.templatetime``: If ``True`` expand ``omero.web.oauth.group.name`` using ``strftime`` to enable time-based groups, default disabled
- ``omero.web.oauth.group.perms``: Permissions on default group for new users if it doesn't exist

Restart OMERO.web in the usual way.

::

    $ omero web restart


Users will be able to sign-in using OAuth at http://omero.web.host/oauth.


Configuration Examples
----------------------

After editing an example file you can apply the configuration:

::

    $ omero load github-example.omero

- `GitHub: github-example.omero <github-example.omero>`_


Development
-----------

OAuth2 requires https to be used throughout.
During development you can disable this by setting an environment variable ``OAUTHLIB_INSECURE_TRANSPORT=1``.


Release process
---------------

Use `bumpversion
<https://pypi.org/project/bump2version/>`_ to increment the version, commit and tag the repo.

::

    $ bumpversion patch
    $ git push origin master
    $ git push --tags


License
-------

OMERO.oauth is released under the AGPL.

Copyright
---------

2019, The Open Microscopy Environment
