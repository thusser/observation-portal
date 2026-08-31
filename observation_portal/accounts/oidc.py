import logging

from django.conf import settings
from django.utils.http import urlencode
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from observation_portal.accounts.models import Profile

logger = logging.getLogger(__name__)


class ObservationPortalOIDCBackend(OIDCAuthenticationBackend):
    """Resolves an OIDC identity (any compliant provider, not just Keycloak) to a portal User.

    Join order: `sub` claim against `Profile.oidc_sub` (stable across email/username changes),
    falling back to the base class's email match on first login. New users are minted inactive,
    same as today's self-registration gate — nothing here bypasses it.
    """

    def filter_users_by_claims(self, claims):
        sub = claims.get('sub')
        if sub:
            matches = self.UserModel.objects.filter(profile__oidc_sub=sub)
            if matches.exists():
                return matches
        return super().filter_users_by_claims(claims)

    def verify_claims(self, claims):
        if not super().verify_claims(claims):
            return False
        # `claims` here comes from the userinfo endpoint (get_userinfo), not the ID token -- the
        # OIDC spec doesn't require userinfo responses to include `aud` (unlike ID tokens, where
        # it's mandatory), and providers vary on whether they do. So this verifies aud *when
        # present* rather than requiring it -- mozilla-django-oidc's own ID-token verification
        # (_verify_jws) explicitly skips aud checking (`verify_aud: False`), so this is still a
        # net improvement, just not a guarantee for providers whose userinfo omits aud.
        aud = claims.get('aud')
        if aud is None:
            return True
        if isinstance(aud, str):
            aud = [aud]
        if self.OIDC_RP_CLIENT_ID not in aud:
            logger.warning('OIDC login rejected: aud claim does not include our client id')
            return False
        return True

    def create_user(self, claims):
        username = self.get_username(claims)
        user = self.UserModel.objects.create_user(
            username, email=claims.get('email', ''), is_active=False,
        )
        Profile.objects.create(
            user=user, institution='', title='', oidc_sub=claims.get('sub', ''),
        )
        return user

    def update_user(self, user, claims):
        sub = claims.get('sub', '')
        if sub and user.profile.oidc_sub != sub:
            user.profile.oidc_sub = sub
            user.profile.save(update_fields=['oidc_sub'])
        return user


def oidc_op_logout_url(request):
    """Builds the OP's RP-initiated end-session URL for OIDC_OP_LOGOUT_URL_METHOD.

    Only wired up when OIDC_OP_LOGOUT_ENDPOINT is configured -- some providers don't expose
    end-session support, in which case OIDCLogoutView falls back to an ordinary local logout.
    """
    logout_endpoint = getattr(settings, 'OIDC_OP_LOGOUT_ENDPOINT', '')
    if not logout_endpoint:
        return settings.LOGOUT_REDIRECT_URL

    id_token = request.session.get('oidc_id_token')
    params = {
        'post_logout_redirect_uri': request.build_absolute_uri(settings.LOGOUT_REDIRECT_URL),
    }
    if id_token:
        params['id_token_hint'] = id_token
    client_id = getattr(settings, 'OIDC_RP_CLIENT_ID', '')
    if client_id:
        params['client_id'] = client_id
    return f'{logout_endpoint}?{urlencode(params)}'
