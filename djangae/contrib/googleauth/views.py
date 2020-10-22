import datetime
import logging

from django.conf import settings
from django.contrib import auth
from django.http import (
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils import timezone
from google.auth.transport import requests
from google.oauth2 import id_token

from oauthlib.oauth2.rfc6749.errors import MismatchingStateError
from requests_oauthlib import OAuth2Session

from . import (
    _CLIENT_ID_SETTING,
    _CLIENT_SECRET_SETTING,
    _DEFAULT_SCOPES_SETTING,
    _pop_scopes,
)
from .backends.oauth2 import OAuthBackend
from .models import OAuthUserSession

STATE_SESSION_KEY = 'oauth-state'
_DEFAULT_OAUTH_SCOPES = [
    "openid",
    "profile",
    "email"
]
AUTHORIZATION_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"

GOOGLE_USER_INFO = "https://www.googleapis.com/oauth2/v1/userinfo"

# The time in seconds that we take away from the given
# expires_in value to account for delay from the server
# to the application. "expires_in" is relative to the time
# the token was granted, not the time we process it
_TOKEN_EXPIRATION_GUARD_TIME = 5


def _get_default_scopes():
    return getattr(settings, _DEFAULT_SCOPES_SETTING, _DEFAULT_OAUTH_SCOPES)


def oauth_login(request):
    """
        This view should be set as your login_url for using OAuth
        authentication. It will trigger the main oauth flow.
    """
    original_url = f"{request.scheme}://{request.META['HTTP_HOST']}{reverse('googleauth_oauth2callback')}"

    scopes = _get_default_scopes()
    additional_scopes, offline = _pop_scopes(request)
    scopes = set(scopes).union(set(additional_scopes))

    next_url = request.GET.get('next')

    if next_url:
        request.session[auth.REDIRECT_FIELD_NAME] = next_url

    client_id = getattr(settings, _CLIENT_ID_SETTING)
    assert client_id

    google = OAuth2Session(client_id, scope=scopes, redirect_uri=original_url)

    kwargs = {
        "prompt": "select_account",
        "include_granted_scopes": 'true'
    }

    if offline:
        kwargs["access_type"] = "offline"

    authorization_url, state = google.authorization_url(
        AUTHORIZATION_BASE_URL,
        **kwargs
    )

    request.session[STATE_SESSION_KEY] = state

    return HttpResponseRedirect(authorization_url)


def _calc_expires_at(expires_in):
    """
        Given an expires_in seconds time from
        the Google OAuth2 authentication process,
        this returns an actual datetime of when
        the expiration is, relative to the current time
    """

    if not expires_in:
        # Already expired
        return timezone.now()

    try:
        expires_in = int(expires_in)
    except (TypeError, ValueError):
        return timezone.now()

    expires_in -= _TOKEN_EXPIRATION_GUARD_TIME
    return timezone.now() + datetime.timedelta(seconds=expires_in)


def oauth2callback(request):
    original_url = f"{request.scheme}://{request.META['HTTP_HOST']}{reverse('googleauth_oauth2callback')}"
    logging.info('Auth callback: Start'.format(STATE_SESSION_KEY))

    if STATE_SESSION_KEY not in request.session:
        logging.error('Auth callback: STATE_SESSION_KEY: {}'.format(STATE_SESSION_KEY))
        return HttpResponseBadRequest()

    client_id = getattr(settings, _CLIENT_ID_SETTING)
    client_secret = getattr(settings, _CLIENT_SECRET_SETTING)

    assert client_id and client_secret

    google = OAuth2Session(
        client_id,
        state=request.session[STATE_SESSION_KEY],
        redirect_uri=original_url
    )

    # If we have a next_url, then on error we can redirect there
    # as that will likely restart the flow, if not, we'll raise
    # a bad request on error
    has_next_url = auth.REDIRECT_FIELD_NAME in request.session

    next_url = (
        request.session[auth.REDIRECT_FIELD_NAME]
        if has_next_url
        else settings.LOGIN_REDIRECT_URL
    )

    failed = False

    try:
        logging.error('Auth callback: FETCHING TOKEN.')
        token = google.fetch_token(
            TOKEN_URL,
            client_secret=client_secret,
            authorization_response=request.build_absolute_uri()
        )
    except MismatchingStateError:
        logging.exception("Mismatched state error in oauth handling")
        failed = True

    if google.authorized:
        logging.info('Auth callback: Goog authorized')
        try:
            profile = id_token.verify_oauth2_token(
                token['id_token'],
                requests.Request(),
                client_id
            )
        except ValueError:
            logging.exception("Error verifying OAuth2 token")
            failed = True
        else:
            pk = profile["sub"]

            defaults = dict(
                access_token=token['access_token'],
                token_type=token['token_type'],
                expires_at=_calc_expires_at(token['expires_in']),
                profile=profile,
                scopes=token['scope']
            )

            # Refresh tokens only exist on the first authorization
            # or, if you've specified the access_type as "offline"
            if 'refresh_token' in token:
                defaults['refresh_token'] = token['refresh_token']

            logging.info('Auth callback: creating session')
            session, _ = OAuthUserSession.objects.update_or_create(
                pk=pk,
                defaults=defaults
            )

            # credentials are valid, we should authenticate the user
            user = OAuthBackend().authenticate(request, oauth_session=session)
            logging.info('Auth callback: Authenticated user {}'.format(user.__dict__))
            if user:
                logging.debug("Successfully authenticated %s via OAuth2", user)

                user.backend = 'djangae.contrib.googleauth.backends.oauth2.%s' % OAuthBackend.__name__

                # If we successfully authenticate, then we need to logout
                # and back in again. This is because the user may have
                # authenticated with another backend, but we need to re-auth
                # with the OAuth backend
                if request.user.is_authenticated:
                    # We refresh as authenticate may have changed the user
                    # and if logout ever does a save we might lose that
                    request.user.refresh_from_db()
                    auth.logout(request)

                auth.login(request, user)
            else:
                failed = True
                logging.warning(
                    "Failed Django authentication after getting oauth credentials"
                )
    else:
        failed = True
        logging.warning(
            "Something failed during the OAuth authorization process for user: %s",
        )

    if failed and not has_next_url:
        return HttpResponseBadRequest()

    # We still redirect to the next_url, as this should trigger
    # the oauth flow again, if we didn't authenticate
    # successfully.
    return HttpResponseRedirect(next_url)
