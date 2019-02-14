#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.conf.urls import url, patterns
from . import views


urlpatterns = patterns(
    'django.views.generic.simple',

    url(r'^$', views.index, name="oauth_index"),
    url(r'^callback$', views.callback, name="oauth_callback"),

    url(r'^test_login/(?P<username>[a-zA-Z0-9-]+)$', views.test_login,
        name="test_login"),
)
