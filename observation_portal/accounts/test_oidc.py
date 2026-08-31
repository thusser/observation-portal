from unittest.mock import patch

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

from observation_portal.accounts.context_processors import oidc as oidc_context_processor
from observation_portal.accounts.models import Profile
from observation_portal.accounts.oidc import (
    ObservationPortalOIDCAuthentication,
    ObservationPortalOIDCBackend,
    ObservationPortalOIDCCallbackView,
    oidc_username_from_email,
)
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

    def test_create_user_lands_inactive_without_auto_activate_groups_configured(self):
        user = self.backend.create_user({'email': 'a@example.com', 'groups': ['/anything']})
        self.assertFalse(user.is_active)

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_AUTO_ACTIVATE_GROUPS=['/trusted'])
    def test_create_user_auto_activates_member_of_configured_group(self):
        user = self.backend.create_user({'email': 'a@example.com', 'groups': ['/trusted', '/other']})
        self.assertTrue(user.is_active)

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_AUTO_ACTIVATE_GROUPS=['/trusted'])
    def test_create_user_does_not_auto_activate_non_member(self):
        user = self.backend.create_user({'email': 'a@example.com', 'groups': ['/other']})
        self.assertFalse(user.is_active)

    @override_settings(**OIDC_TEST_SETTINGS, OIDC_AUTO_ACTIVATE_GROUPS=['/trusted', '/also-required'])
    def test_create_user_auto_activate_requires_all_configured_groups(self):
        # AND, not OR -- same semantics as OIDC_REQUIRED_GROUPS.
        user = self.backend.create_user({'email': 'a@example.com', 'groups': ['/trusted']})
        self.assertFalse(user.is_active)


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


@override_settings(**OIDC_TEST_SETTINGS, OIDC_ENABLED=True)
class TestOidcContextProcessorNextParam(TestCase):
    """next is read from POST as well as GET: after a failed local-password submission the login
    form re-renders via POST, carrying `next` forward as a hidden field -- GET-only silently
    dropped the OIDC button's redirect destination on that re-render.

    reverse('oidc_authentication_init') is patched out: the real URL pattern only exists when
    OIDC_ENABLED was true at urls.py's own import time (settings-module-import time, before any
    test's override_settings runs -- see TestOIDCDRFAuthenticationStacking's docstring for the
    same constraint elsewhere), which isn't the case in this test run. Irrelevant to what's under
    test here (the next-param precedence logic), so a fixed dummy return is fine.
    """

    def _oidc_login_url(self, request):
        with patch('observation_portal.accounts.context_processors.reverse', return_value='/oidc/authenticate/'):
            return oidc_context_processor(request)['oidc_login_url']

    def test_reads_next_from_get(self):
        request = RequestFactory().get('/accounts/login/?next=/foo')
        self.assertIn('next=%2Ffoo', self._oidc_login_url(request))

    def test_reads_next_from_post(self):
        request = RequestFactory().post('/accounts/login/', {'next': '/foo'})
        self.assertIn('next=%2Ffoo', self._oidc_login_url(request))

    def test_post_takes_precedence_over_get(self):
        # Matches Django's own AuthenticationForm/LoginView convention of trusting the submitted
        # form field over the URL on a POST.
        request = RequestFactory().post('/accounts/login/?next=/from-get', {'next': '/from-post'})
        self.assertIn('next=%2Ffrom-post', self._oidc_login_url(request))


class TestOidcUsernameFromEmail(TestCase):
    def test_uses_email_local_part(self):
        self.assertEqual(oidc_username_from_email('alice@example.com'), 'alice')

    def test_sanitizes_disallowed_characters(self):
        self.assertEqual(oidc_username_from_email('a+lice!!@example.com'), 'a+lice')

    def test_falls_back_for_missing_email(self):
        self.assertEqual(oidc_username_from_email(''), 'oidc-user')
        self.assertEqual(oidc_username_from_email(None), 'oidc-user')

    def test_deduplicates_on_collision(self):
        blend_user(user_params={'username': 'alice'})

        self.assertEqual(oidc_username_from_email('alice@example.com'), 'alice2')

    def test_deduplicates_multiple_collisions(self):
        blend_user(user_params={'username': 'alice'})
        blend_user(user_params={'username': 'alice2'})

        self.assertEqual(oidc_username_from_email('alice@example.com'), 'alice3')


class TestObservationPortalOIDCCallbackView(TestCase):
    """login_failure's job: distinguish "pending activation" (self.user set but inactive) from
    every other failure (self.user is None -- bad state, rejected claims, provider error, ...),
    which the base view's plain redirect can't do."""

    @staticmethod
    def _view_with_user(user):
        view = ObservationPortalOIDCCallbackView()
        view.request = RequestFactory().get('/oidc/callback/')
        view.user = user
        return view

    def test_renders_pending_activation_page_for_inactive_user(self):
        user = blend_user(user_params={'is_active': False})

        response = self._view_with_user(user).login_failure()

        self.assertEqual(response.status_code, 403)
        self.assertIn(b'pending activation', response.content.lower())

    def test_falls_back_to_default_failure_for_no_user(self):
        response = self._view_with_user(None).login_failure()

        self.assertEqual(response.status_code, 302)

    def test_falls_back_to_default_failure_for_active_user(self):
        # Shouldn't normally happen -- login_failure is only reached when login didn't succeed --
        # but verify it doesn't wrongly render the pending-activation page for an active user.
        user = blend_user()

        response = self._view_with_user(user).login_failure()

        self.assertEqual(response.status_code, 302)
