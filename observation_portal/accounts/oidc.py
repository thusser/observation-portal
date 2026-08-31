import logging

from django.conf import settings
from django.utils.http import urlencode
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.contrib.drf import OIDCAuthentication
from requests.exceptions import RequestException
from rest_framework.exceptions import AuthenticationFailed

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
        # Linking an OIDC identity to an *existing* account by email is a trust boundary: if the
        # OP explicitly says it hasn't verified the email (`email_verified: False`), refuse the
        # link rather than silently handing that account to whoever controls the address at the
        # OP. Not every provider sends this claim -- when it's absent we trust the OP verified
        # it, the same assumption every other email-based account-linking flow makes. This only
        # gates the email-fallback match below; a brand new account (create_user) carries no
        # such risk since nothing existing is being linked.
        if claims.get('email_verified') is False:
            logger.warning('OIDC login rejected: email_verified is explicitly False')
            return self.UserModel.objects.none()
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
        if aud is not None:
            if isinstance(aud, str):
                aud = [aud]
            if self.OIDC_RP_CLIENT_ID not in aud:
                logger.warning('OIDC login rejected: aud claim does not include our client id')
                return False

        # Optional group-based authorization gate (mirrors pyobs-auth's REQUIRED_GROUPS): unset
        # -> every authenticated identity is allowed, matching today's default. Checked on every
        # login, not just account creation, so someone who's since left the group is rejected on
        # their next login too, not just blocked from minting a new account. Requires a "Group
        # Membership" mapper on the OIDC client with "Add to userinfo" enabled -- claims here
        # come from the userinfo endpoint, not the ID/access token.
        required_groups = getattr(settings, 'OIDC_REQUIRED_GROUPS', ())
        if required_groups:
            groups = set(claims.get('groups') or [])
            if not all(group in groups for group in required_groups):
                logger.warning('OIDC login rejected: missing required group membership')
                return False

        return True

    def create_user(self, claims):
        username = self.get_username(claims)
        user = self.UserModel.objects.create_user(
            username, email=claims.get('email', ''), is_active=False,
        )
        # sub is mandatory per the OIDC spec, so an empty value only happens against a
        # non-compliant provider -- store None, not '', so a second such user doesn't collide
        # with Profile.oidc_sub's unique constraint.
        Profile.objects.create(
            user=user, institution='', title='', oidc_sub=claims.get('sub') or None,
        )
        return user

    def update_user(self, user, claims):
        sub = claims.get('sub')
        if not sub:
            return user
        # user.profile can raise RelatedObjectDoesNotExist for accounts that predate the
        # Profile model requirement (e.g. createsuperuser), which would otherwise 500 a first
        # OIDC login that happens to email-match one of those.
        profile = Profile.objects.filter(user=user).first()
        if profile and profile.oidc_sub != sub:
            profile.oidc_sub = sub
            profile.save(update_fields=['oidc_sub'])
        return user

    def get_or_create_user(self, access_token, id_token, payload):
        """Enforce is_active the same way for every entry point.

        The base implementation returns whatever user filter_users_by_claims/create_user hands
        back regardless of is_active -- fine for the browser flow, which separately checks
        is_active before completing login (OIDCAuthenticationCallbackView.login_success), but the
        DRF flow (ObservationPortalOIDCAuthentication below) has no such check: IsAuthenticated
        passes for any authenticated user object, active or not. Returning None here for an
        inactive match makes DRF's contrib.drf.OIDCAuthentication raise AuthenticationFailed
        instead, matching the browser flow's activation gate.
        """
        user = super().get_or_create_user(access_token, id_token, payload)
        if user and not user.is_active:
            return None
        return user


class ObservationPortalOIDCAuthentication(OIDCAuthentication):
    """mozilla-django-oidc's DRF authenticator only catches HTTPError/SuspiciousOperation around
    the userinfo call -- a transport-level failure (timeout, connection refused, DNS failure)
    talking to the OIDC provider would otherwise propagate as an uncaught exception (a 500 on
    what should be a clean auth failure) instead of translating to AuthenticationFailed like
    every other rejected-credential case."""

    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except RequestException as exc:
            logger.warning('OIDC userinfo request failed: %s', exc)
            raise AuthenticationFailed('OIDC provider unreachable')


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
