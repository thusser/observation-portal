import responses
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django_dramatiq.test import DramatiqTestCase
from mozilla_django_oidc.contrib.drf import OIDCAuthentication
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from oauth2_provider.models import AccessToken, Application
from django.utils import timezone
from datetime import timedelta
from rest_framework.request import Request

from observation_portal.accounts.oidc import ObservationPortalOIDCBackend
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

    def test_create_user_mints_inactive_user_with_empty_profile(self):
        claims = {'email': 'newperson@example.com', 'sub': 'abc-123'}
        user = self.backend.create_user(claims)

        self.assertFalse(user.is_active)
        self.assertEqual(user.email, 'newperson@example.com')
        self.assertEqual(user.profile.institution, '')
        self.assertEqual(user.profile.title, '')
        self.assertEqual(user.profile.oidc_sub, 'abc-123')

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


class TestOIDCDRFAuthenticationStacking(TestCase):
    """Authenticator-order stacking, as it would be with OIDC_ENABLED=True.

    Exercises OAuth2Authentication/OIDCAuthentication directly against a DRF Request (rather than
    hitting a real view through the test client): DRF views bind `authentication_classes` from
    api_settings.DEFAULT_AUTHENTICATION_CLASSES once, at class-definition time (during app
    startup, well before any test's override_settings runs) -- REST_FRAMEWORK isn't one of the
    settings override_settings can retroactively change on an already-defined view (DRF's own
    APISettings docstring: "test helpers like override_settings may not work as expected"). Going
    straight at the authenticators sidesteps that and tests the actual thing this stacking depends
    on: authenticator order, not view configuration.
    """

    def setUp(self):
        self.user = blend_user()
        self.factory = RequestFactory()

    @staticmethod
    def _authenticators():
        # matches settings.py's ordering: OAuth2Authentication before OIDCAuthentication.
        return [OAuth2Authentication(), OIDCAuthentication()]

    @override_settings(**OIDC_TEST_SETTINGS, AUTHENTICATION_BACKENDS=OIDC_AUTHENTICATION_BACKENDS)
    def test_valid_oidc_bearer_token_authenticates(self):
        responses.add(
            responses.GET, 'https://op.example.com/userinfo',
            json={'email': self.user.email, 'sub': 'some-sub'}, status=200,
        )
        django_request = self.factory.get('/api/profile/', HTTP_AUTHORIZATION='Bearer some-valid-access-token')

        request = Request(django_request, authenticators=self._authenticators())

        self.assertEqual(request.user, self.user)
        self.assertIsInstance(request.successful_authenticator, OIDCAuthentication)

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
        # token first, OIDCAuthentication would attempt an unmocked HTTP call and `responses`
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
        self.assertNotContains(response, 'oidc')
