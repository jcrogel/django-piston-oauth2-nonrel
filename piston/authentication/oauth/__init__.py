import oauth2 as oauth
from django.conf import settings
from django.http import HttpResponse
from django.template import loader

from piston.authentication.oauth.store import store, InvalidAccessToken, InvalidConsumer
from piston.authentication.oauth.utils import get_oauth_request, verify_oauth_request


class OAuthAuthentication(object):
    def __init__(self, realm='API'):
        self.realm = realm

    def is_authenticated(self, request):
        oauth_request = get_oauth_request(request)

        try:
            consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
            access_token = store.get_access_token(request, oauth_request, consumer, oauth_request['oauth_token'])
        except (InvalidConsumer, InvalidAccessToken):
            return False
    
        if not verify_oauth_request(request, oauth_request, consumer, access_token):
            return False

        request.user = store.get_user_from_access_token(request, oauth_request, access_token)
        request.consumer = store.get_consumer_from_access_token(request, oauth_request, access_token)
        request.throttle_extra = request.consumer.key

        return True
        
    def challenge(self):
        """
        Returns a 401 response with a small bit on
        what OAuth is, and where to learn more about it.
        
        When this was written, browsers did not understand
        OAuth authentication on the browser side, and hence
        the helpful template we render. Maybe some day in the
        future, browsers will take care of this stuff for us
        and understand the 401 with the realm we give it.
        """
        response = HttpResponse()
        response.status_code = 401

        for k, v in oauth.build_authenticate_header(realm=self.realm).iteritems():
            response[k] = v

        tmpl = loader.render_to_string('piston/oauth/challenge.html',
            { 'MEDIA_URL': settings.MEDIA_URL })

        response.content = tmpl

        return response