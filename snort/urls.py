from django.conf.urls import patterns, include, url
from views import *

urlpatterns = patterns('',
    
    url(r'^$', index_show, name='index_show'),
    url(r'^about/$', about_show, name='about_show'),
    url(r'^process/$', process_show, name='process_show'),
    url(r'^rules/$', rules_show, name='rules_show'),
    url(r'^alert/$', alert_show, name='alert_show'),
    url(r'^process/start$', process_start, name='process_start'),
    url(r'^process/kill$', process_kill, name='process_kill'),
    url(r'^process/restart$', process_restart, name='process_restart'),
    url(r'^rules/add$', rules_add, name='rules_add'),
    url(r'^rules/edit$', rules_edit, name='rules_edit'),
    url(r'^rules/del$', rules_del, name='rules_del'),
   )