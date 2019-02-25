#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.conf.urls import url, patterns
from . import views


urlpatterns = patterns(
    'django.views.generic.simple',

    url(r'^$', views.OauthLoginView.as_view(), name="oauth_index"),
    url(r'^callback/(?P<name>[a-z][a-z0-9]+)$',
        views.OauthCallbackView.as_view(), name="oauth_callback"),

    url(r'^confirm$', views.confirm, name="oauth_confirm"),

    url(r'^sessiontoken$', views.sessiontoken, name="oauth_sessiontoken"),
)
