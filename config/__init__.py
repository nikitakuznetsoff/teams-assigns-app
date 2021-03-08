class FlaskConfig:
    SESSION_TYPE = "filesystem"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True


class AppConfig:
    CLIENT_ID = "337d973a-0cfa-4430-9b97-69073cd6e729"
    CLIENT_SECRET = "A-o5M.~m3i-YoV9IJE3H2zmhDjn~7xgxD_"
    TENANT = "dac443f8-0f2f-4715-b3b2-e16bf480363a"
    SCOPE = ["https://graph.microsoft.com/.default"]
    AUTHORITY = "https://login.microsoftonline.com/"+TENANT
    # AUTHORIZE_ENDPOINT = "/oauth2/v2.0/authorize"
    # TOKEN_ENDPOINT = "/oauth2/v2.0/token"
    BASE_URI = "https://f339d1a60a00.ngrok.io"
    REQUEST_URI = "https://f339d1a60a00.ngrok.io/token"
    # SYNC_URI = "https://194.87.110.241:5005"
    SYNC_URI = "http://localhost:5000"