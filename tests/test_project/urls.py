from django.conf.urls import *


urlpatterns = patterns('',
    url(r'api/', include('test_project.apps.testapp.urls'))
)
