from urllib import urlencode

import oauth2 as oauth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, HttpResponseForbidden
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate

from piston.authentication.oauth.forms import AuthorizeRequestTokenForm
from piston.authentication.oauth.store import store, InvalidConsumerError, InvalidTokenError
from piston.authentication.oauth.utils import verify_oauth_request, get_oauth_request, require_params


@csrf_exempt
def get_request_token(request):
    oauth_request = get_oauth_request(request)

    missing_params = require_params(oauth_request, ('oauth_callback',))
    if missing_params is not None:
        return missing_params

    try:
        consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
    except InvalidConsumerError:
        return HttpResponseBadRequest('Invalid Consumer.')

    if not verify_oauth_request(request, oauth_request, consumer):
        return HttpResponseBadRequest('Could not verify OAuth request.')

    request_token = store.create_request_token(request, oauth_request, consumer, oauth_request['oauth_callback'])

    ret = urlencode({
        'oauth_token': request_token.key,
        'oauth_token_secret': request_token.secret,
        'oauth_callback_confirmed': 'true'
    })
    return HttpResponse(ret, content_type='application/x-www-form-urlencoded')


@login_required
def authorize_request_token(request, form_class=AuthorizeRequestTokenForm, template_name='piston/oauth/authorize.html', verification_template_name='piston/oauth/authorize_verification_code.html'):
    if 'oauth_token' not in request.REQUEST:
        return HttpResponseBadRequest('No request token specified.')

    oauth_request = get_oauth_request(request)

    try:
        request_token = store.get_request_token(request, oauth_request, request.REQUEST['oauth_token'])
    except InvalidTokenError:
        return HttpResponseBadRequest('Invalid request token.')

    consumer = store.get_consumer_for_request_token(request, oauth_request, request_token)

    if request.method == 'POST':
        form = form_class(request.POST)
        if form.is_valid() and form.cleaned_data['authorize_access']:
            request_token = store.authorize_request_token(request, oauth_request, request_token)
            if request_token.callback is not None and request_token.callback != 'oob':
                return HttpResponseRedirect('%s&%s' % (request_token.get_callback_url(), urlencode({'oauth_token': request_token.key})))
            else:
                return render_to_response(verification_template_name, {'consumer': consumer, 'verification_code': request_token.verifier}, RequestContext(request))
    else:
        form = form_class(initial={'oauth_token': request_token.key})

    return render_to_response(template_name, {'consumer': consumer, 'form': form}, RequestContext(request))


@csrf_exempt
def get_access_token(request):
    oauth_request = get_oauth_request(request)
    is_xauth = 'x_auth_mode' in oauth_request

    if is_xauth:
        if oauth_request['x_auth_mode'] != 'client_auth':
            return HttpResponseBadRequest('Invalid x_auth_mode value, expected "client_auth".')
        missing_params = require_params(oauth_request, ('x_auth_username', 'x_auth_password'))
    else:
        missing_params = require_params(oauth_request, ('oauth_token', 'oauth_verifier'))

    if missing_params is not None:
        return missing_params

    try:
        consumer = store.get_consumer(request, oauth_request, oauth_request['oauth_consumer_key'])
    except InvalidConsumerError:
        return HttpResponseBadRequest('Invalid consumer.')

    if is_xauth:
        if not consumer.xauth_allowed:
            return HttpResponseForbidden('xAuth not allowed for this consumer.')
        request_token = None
    else:
        try:
            request_token = store.get_request_token(request, oauth_request, oauth_request['oauth_token'])
        except InvalidTokenError:
            return HttpResponseBadRequest('Invalid request token.')

    if not verify_oauth_request(request, oauth_request, consumer, request_token):
        return HttpResponseBadRequest('Could not verify OAuth request.')

    if not is_xauth and oauth_request.get('oauth_verifier', None) != request_token.verifier:
        return HttpResponseBadRequest('Invalid OAuth verifier.')

    if is_xauth:
        xauth_user = oauth_request['x_auth_username']
        xauth_pass = oauth_request['x_auth_password']
        user = authenticate(username=xauth_user, password=xauth_pass)
        if user and user.is_active:
            access_token = store.create_access_token_for_user(request, oauth_request, consumer, user)
        else:
            return HttpResponseForbidden('xAuth username/password combination invalid.')
    else:
        access_token = store.create_access_token(request, oauth_request, consumer, request_token)

    ret = urlencode({
        'oauth_token': access_token.key,
        'oauth_token_secret': access_token.secret,
        'userid': access_token.user.id,
        'screen_name': access_token.user.visible_name,
    })

    return HttpResponse(ret, content_type='application/x-www-form-urlencoded')

