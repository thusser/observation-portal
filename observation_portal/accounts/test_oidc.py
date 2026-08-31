import responses
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django_dramatiq.test import DramatiqTestCase
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from oauth2_provider.models import AccessToken, Application
from django.utils import timezone
from datetime import timedelta
from requests.exceptions import ConnectionError as RequestsConnectionError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from observation_portal.accounts.models import Profile
from observation_portal.accounts.oidc import ObservationPortalOIDCAuthentication, ObservationPortalOIDCBackend
from observation_portal.accounts.test_utils import blend_user

OIDC_AUTHENTICATION_BACKENDS = [
    'observation_portal.accounts.backends.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend',
    'oauth2_provider.backends.OAuth2Backend',
    'observation_portal.accounts.oidc.ObservationPortalOIDCBackend',
]


OIDC_TEST_SETTINGS = dict(
    OIDC_RP_CLIENT_ID='test-client',
    OIDC_RP_CLIENT_SECRET='test-secret',
    OIDC_OP_AUTHORIZATION_ENDPOINT='https://op.example.com/auth',
    OIDC_OP_TOKEN_ENDPOINT='https://op.example.com/token',
    OIDC_OP_USER_ENDPOINT='https://op.example.com/userinfo',
    OIDC_OP_JWKS_ENDPOINT='https://op.example.com/jwks',
    OIDC_RP_SIGN_ALGO='RS256',
)


@override_settings(**OIDC_TEST_SETTINGS)
class TestObservationPortalOIDCBackend(DramatiqTestCase):
    """DramatiqTestCase (not plain TestCase): create_user/update_user save a Profile, which fires
    cb_profile_post_save -- a real dramatiq enqueue that would otherwise need a live broker."""

    def setUp(self):
        super().setUp()
        self.backend = ObservationPortalOIDCBackend()

    def test_verify_claims_accepts_matching_audience(self):
        self.assertTrue(self.backend.verify_claims({'email': 'a@example.com', 'aud': 'test-client'}))

    def test_verify_claims_accepts_audience_list(self):
        self.assertTrue(self.backend.verify_claims({'email': 'a@example.com', 'aud': ['other', 'test-client']}))

    def test_verify_claims_accepts_missing_audience(self):
        # Not all OIDC providers' userinfo responses include `aud` (only ID tokens are required
        # to) -- verify_claims must not reject those, only ones with a mismatched aud.
        self.assertTrue(self.backend.verify_claims({'email': 'a@example.com'}))

    def test_verify_claims_rejects_wrong_audience(self):
        self.assertFalse(self.backend.verify_claims({'email': 'a@example.com', 'aud': 'someone-else'}))

    def test_verify_claims_rejects_missing_email(self):
        self.assertFalse(self.backend.verify_claims({'aud': 'test-client'}))

    def test_verify_claims_no_required_groups_configured_allows_any_groups(self):
        # OIDC_REQUIRED_GROUPS unset in OIDC_TEST_SETTINGS -- default behavior, gate never applies.
        self.assertTrue(self.backend.verify_claims({'email': 'a@example.com', 'groups': []}))
        self.assertTrue(self.backend.verify_claims({'email': 'a@example.com'}))

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_REQUIRED_GROUPS=['/monet-iag50'])
    def test_verify_claims_accepts_member_of_required_group(self):
        self.assertTrue(self.backend.verify_claims(
            {'email': 'a@example.com', 'groups': ['/monet-iag50', '/something-else']},
        ))

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_REQUIRED_GROUPS=['/monet-iag50'])
    def test_verify_claims_rejects_non_member(self):
        self.assertFalse(self.backend.verify_claims(
            {'email': 'a@example.com', 'groups': ['/something-else']},
        ))

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_REQUIRED_GROUPS=['/monet-iag50'])
    def test_verify_claims_rejects_missing_groups_claim(self):
        # No "Group Membership" mapper configured on the client (or not added to userinfo) --
        # must fail closed, not silently allow everyone through.
        self.assertFalse(self.backend.verify_claims({'email': 'a@example.com'}))

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_REQUIRED_GROUPS=['/monet-iag50', '/observers'])
    def test_verify_claims_requires_all_configured_groups(self):
        # AND, not OR -- matches pyobs-auth's REQUIRED_GROUPS semantics.
        self.assertFalse(self.backend.verify_claims(
            {'email': 'a@example.com', 'groups': ['/monet-iag50']},
        ))
        self.assertTrue(self.backend.verify_claims(
            {'email': 'a@example.com', 'groups': ['/monet-iag50', '/observers']},
        ))

    def test_create_user_mints_inactive_user_with_empty_profile(self):
        claims = {'email': 'newperson@example.com', 'sub': 'abc-123'}
        user = self.backend.create_user(claims)

        self.assertFalse(user.is_active)
        self.assertEqual(user.email, 'newperson@example.com')
        self.assertEqual(user.profile.institution, '')
        self.assertEqual(user.profile.title, '')
        self.assertEqual(user.profile.oidc_sub, 'abc-123')

    def test_create_user_stores_none_not_empty_string_for_missing_sub(self):
        # sub is mandatory per spec, so this only happens against a non-compliant provider -- but
        # Profile.oidc_sub is unique, so a second such user must not collide on ''.
        first = self.backend.create_user({'email': 'one@example.com'})
        second = self.backend.create_user({'email': 'two@example.com'})

        self.assertIsNone(first.profile.oidc_sub)
        self.assertIsNone(second.profile.oidc_sub)

    def test_filter_users_by_claims_matches_by_sub_first(self):
        user = blend_user(profile_params={'oidc_sub': 'sub-1'})
        # a different user matches by email too -- sub match must win, not raise on multiple matches
        other = blend_user(user_params={'email': user.email})

        matches = self.backend.filter_users_by_claims({'sub': 'sub-1', 'email': user.email})

        self.assertEqual(list(matches), [user])

    def test_filter_users_by_claims_falls_back_to_email(self):
        user = blend_user(profile_params={'oidc_sub': ''})

        matches = self.backend.filter_users_by_claims({'sub': 'unseen-sub', 'email': user.email})

        self.assertEqual(list(matches), [user])

    def test_filter_users_by_claims_rejects_unverified_email(self):
        user = blend_user(profile_params={'oidc_sub': ''})

        matches = self.backend.filter_users_by_claims(
            {'sub': 'unseen-sub', 'email': user.email, 'email_verified': False},
        )

        self.assertEqual(list(matches), [])

    def test_update_user_stores_sub_on_first_oidc_login(self):
        user = blend_user(profile_params={'oidc_sub': ''})

        self.backend.update_user(user, {'sub': 'freshly-linked'})

        user.refresh_from_db()
        self.assertEqual(user.profile.oidc_sub, 'freshly-linked')

    def test_update_user_leaves_matching_sub_unchanged(self):
        user = blend_user(profile_params={'oidc_sub': 'already-set'})

        # save() call count would matter if this were more expensive; just assert no error /
        # value change for the already-consistent case
        self.backend.update_user(user, {'sub': 'already-set'})

        user.refresh_from_db()
        self.assertEqual(user.profile.oidc_sub, 'already-set')

    def test_update_user_does_not_crash_for_user_without_profile(self):
        # e.g. an account created via createsuperuser, which doesn't go through the
        # Profile-creating registration flow.
        user = self.backend.UserModel.objects.create_user('admin', email='admin@example.com')
        self.assertFalse(Profile.objects.filter(user=user).exists())

        result = self.backend.update_user(user, {'sub': 'some-sub'})

        self.assertEqual(result, user)
        self.assertFalse(Profile.objects.filter(user=user).exists())

    def test_get_or_create_user_returns_none_for_inactive_match(self):
        user = blend_user(user_params={'is_active': False}, profile_params={'oidc_sub': 'inactive-sub'})
        # get_or_create_user (base class) fetches claims via a live userinfo call regardless of
        # what's passed as `payload` -- it only uses payload for the browser/ID-token flow.
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            json={'sub': 'inactive-sub', 'email': user.email}, status=200,
        )

        result = self.backend.get_or_create_user('token', None, None)

        self.assertIsNone(result)

    def test_get_or_create_user_returns_active_match(self):
        user = blend_user(profile_params={'oidc_sub': 'active-sub'})
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            json={'sub': 'active-sub', 'email': user.email}, status=200,
        )

        result = self.backend.get_or_create_user('token', None, None)

        self.assertEqual(result, user)


class TestOIDCDRFAuthenticationStacking(TestCase):
    """Authenticator-order stacking, as it would be with OIDC_ENABLED=True.

    Exercises OAuth2Authentication/ObservationPortalOIDCAuthentication directly against a DRF
    Request (rather than hitting a real view through the test client): DRF views bind
    `authentication_classes` from api_settings.DEFAULT_AUTHENTICATION_CLASSES once, at
    class-definition time (during app startup, well before any test's override_settings runs) --
    REST_FRAMEWORK isn't one of the settings override_settings can retroactively change on an
    already-defined view (DRF's own APISettings docstring: "test helpers like override_settings
    may not work as expected"). Going straight at the authenticators sidesteps that and tests the
    actual thing this stacking depends on: authenticator order, not view configuration.
    """

    def setUp(self):
        self.user = blend_user()
        self.factory = RequestFactory()

    @staticmethod
    def _authenticators():
        # matches settings.py's ordering: OAuth2Authentication before the OIDC authenticator.
        return [OAuth2Authentication(), ObservationPortalOIDCAuthentication()]

    @override_settings(**OIDC_TEST_SETTINGS, AUTHENTICATION_BACKENDS=OIDC_AUTHENTICATION_BACKENDS)
    def test_valid_oidc_bearer_token_authenticates(self):
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            json={'email': self.user.email, 'sub': 'some-sub'}, status=200,
        )
        django_request = self.factory.get('/api/profile/', HTTP_AUTHORIZATION='Bearer some-valid-access-token')

        request = Request(django_request, authenticators=self._authenticators())

        self.assertEqual(request.user, self.user)
        self.assertIsInstance(request.successful_authenticator, ObservationPortalOIDCAuthentication)

    @override_settings(**OIDC_TEST_SETTINGS, AUTHENTICATION_BACKENDS=OIDC_AUTHENTICATION_BACKENDS)
    def test_inactive_oidc_user_does_not_authenticate(self):
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            json={'email': self.user.email, 'sub': 'some-sub'}, status=200,
        )
        django_request = self.factory.get('/api/profile/', HTTP_AUTHORIZATION='Bearer some-valid-access-token')

        request = Request(django_request, authenticators=self._authenticators())

        with self.assertRaises(AuthenticationFailed):
            _ = request.user

    @override_settings(**OIDC_TEST_SETTINGS, AUTHENTICATION_BACKENDS=OIDC_AUTHENTICATION_BACKENDS)
    def test_transport_failure_raises_authentication_failed_not_500(self):
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            body=RequestsConnectionError('connection refused'),
        )
        django_request = self.factory.get('/api/profile/', HTTP_AUTHORIZATION='Bearer some-valid-access-token')

        request = Request(django_request, authenticators=self._authenticators())

        with self.assertRaises(AuthenticationFailed):
            _ = request.user

    @override_settings(**OIDC_TEST_SETTINGS, AUTHENTICATION_BACKENDS=OIDC_AUTHENTICATION_BACKENDS)
    def test_portal_oauth2_token_still_authenticates_without_reaching_oidc(self):
        application = Application.objects.create(
            name='test app', client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_PASSWORD,
        )
        access_token = AccessToken.objects.create(
            user=self.user, application=application, token='portal-issued-token',
            expires=timezone.now() + timedelta(days=1), scope='read',
        )
        # no responses.add() for the userinfo endpoint: if OAuth2Authentication didn't claim this
        # token first, the OIDC authenticator would attempt an unmocked HTTP call and `responses`
        # would raise ConnectionError, failing this test.
        django_request = self.factory.get('/api/profile/', HTTP_AUTHORIZATION=f'Bearer {access_token.token}')

        request = Request(django_request, authenticators=self._authenticators())

        self.assertEqual(request.user, self.user)
        self.assertIsInstance(request.successful_authenticator, OAuth2Authentication)


class TestLoginPageWithoutOIDC(TestCase):
    """OIDC_ENABLED defaults to False in these tests (no env var set) -- confirms the login page
    is unaffected when OIDC isn't configured, matching production's default-off behavior."""

    def test_login_page_has_no_oidc_button(self):
        response = self.client.get(reverse('auth_login'))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['oidc_login_enabled'])
        self.assertNotIn(b'oidc/authenticate', response.content)
