import msal
import app_config


def build_msal_app(cache=None):
    msal_app = msal.ConfidentialClientApplication(
        client_id=app_config.CLIENT_ID,
        authority=app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET,
        token_cache=cache
    )
    return msal_app


