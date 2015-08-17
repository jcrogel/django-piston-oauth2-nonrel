from django.conf.urls import *
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    (r'^', include('blogserver.blog.urls')),
    (r'^api/', include('blogserver.api.urls')),
    (r'^admin/(.*)', admin.site.root),
)
