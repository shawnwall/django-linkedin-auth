from django.conf.urls.defaults import patterns, include, url

urlpatterns = patterns('linkedin_auth.views',
    url(r'^login/?$', 'oauth_login'),
    url(r'^logout/?$', 'oauth_logout'),
    url(r'^login/authenticated/?$', 'oauth_authenticated'),
)
