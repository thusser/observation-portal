from urllib.parse import urlencode

from django.conf import settings
from django.urls import reverse


def oidc(request):
    if not settings.OIDC_ENABLED:
        return {'oidc_login_enabled': False}

    # POST too: after a failed local-password submission the form re-renders via POST, where
    # `next` (if the login form carried it forward) lives in POST, not GET -- GET-only silently
    # dropped the redirect destination for the OIDC button on that re-render.
    next_url = request.POST.get('next') or request.GET.get('next', '')
    login_url = reverse('oidc_authentication_init')
    if next_url:
        login_url = f'{login_url}?{urlencode({"next": next_url})}'

    return {
        'oidc_login_enabled': True,
        'oidc_login_url': login_url,
        'oidc_provider_label': getattr(settings, 'OIDC_PROVIDER_LABEL', 'OIDC'),
    }
