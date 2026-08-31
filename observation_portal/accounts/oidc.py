import logging
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.utils.http import urlencode
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.contrib.drf import OIDCAuthentication
from mozilla_django_oidc.views import OIDCAuthenticationCallbackView
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
        # Mirrors OIDC_REQUIRED_GROUPS's shape and semantics (AND across entries, full group
        # paths). Unset -> every new account still lands inactive pending manual admin review,
        # today's default. Set -> members of ALL of these groups are activated immediately on
        # creation, skipping that review -- meant for a group you already trust to have vetted
        # membership (e.g. the same one gating OIDC_REQUIRED_GROUPS, or a stricter subset of it).
        auto_activate_groups = getattr(settings, 'OIDC_AUTO_ACTIVATE_GROUPS', ())
        is_active = False
        if auto_activate_groups:
            groups = set(claims.get('groups') or [])
            is_active = all(group in groups for group in auto_activate_groups)
        user = self.UserModel.objects.create_user(
            username, email=claims.get('email', ''), is_active=is_active,
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


def oidc_username_from_email(email, claims=None):
    """OIDC_USERNAME_ALGO: mozilla-django-oidc's default (base64(sha1(email))) produces opaque
    usernames -- fine for a system that never shows usernames, but this portal's admin/proposals
    UI does. Uses the email's local part instead, de-duplicated with a numeric suffix on
    collision (two different domains sharing a local part, or a local-part clash with an
    existing local-registration username)."""
    base = re.sub(r'[^a-zA-Z0-9_.@+-]', '', (email or '').split('@')[0]) or 'oidc-user'
    base = base[:150]
    UserModel = get_user_model()
    username = base
    suffix = 1
    while UserModel.objects.filter(username=username).exists():
        suffix += 1
        username = f'{base}{suffix}'[:150]
    return username


class ObservationPortalOIDCCallbackView(OIDCAuthenticationCallbackView):
    """OIDC_CALLBACK_CLASS: distinguishes "your account is pending activation" from every other
    login failure (wrong group, bad state, provider error, etc.), which the base view's generic
    redirect-to-LOGIN_REDIRECT_URL_FAILURE can't -- it only knows self.user is falsy, not why.

    Renders in place rather than adding a new URL, sidestepping any question of whether that URL
    would be reachable given the frontend's own routing of /accounts/ and unrouted paths -- /oidc/
    already reaches this code, unlike most other paths on this site.
    """

    def login_failure(self):
        if getattr(self, 'user', None) is not None and not self.user.is_active:
            return render(self.request, 'registration/oidc_pending_activation.html', status=403)
        return super().login_failure()


class ObservationPortalOIDCAuthentication(OIDCAuthentication):
    """mozilla-django-oidc's DRF authenticator only catches HTTPError/SuspiciousOperation around
    the userinfo call -- a transport-level failure (timeout, connection refused, DNS failure)
    talking to the OIDC provider would otherwise propagate as an uncaught exception (a 500 on
    what should be a clean auth failure) instead of translating to AuthenticationFailed like
    every other rejected-credential case.

    Also enforces is_active here rather than in the shared backend: IsAuthenticated passes for
    any authenticated user object regardless of is_active, so without this an inactive OIDC-minted
    account holding a valid provider token could hit IsAuthenticated-only endpoints. Kept out of
    ObservationPortalOIDCBackend.get_or_create_user (unlike an earlier version of this code) so
    the browser flow's callback view still sees the real (inactive) user object and can render a
    helpful message instead of a bare failure redirect."""

    def authenticate(self, request):
        try:
            result = super().authenticate(request)
        except RequestException as exc:
            logger.warning('OIDC userinfo request failed: %s', exc)
            raise AuthenticationFailed('OIDC provider unreachable')
        if result is not None and not result[0].is_active:
            raise AuthenticationFailed('Account pending activation')
        return result


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
