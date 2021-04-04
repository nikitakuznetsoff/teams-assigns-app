class FlaskConfig:
    SESSION_TYPE = "filesystem"
    SECRET_KEY = "123"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "None"


class AppConfig:
    CLIENT_ID = "337d973a-0cfa-4430-9b97-69073cd6e729"
    CLIENT_SECRET = "A-o5M.~m3i-YoV9IJE3H2zmhDjn~7xgxD_"
    TENANT = "dac443f8-0f2f-4715-b3b2-e16bf480363a"
    SCOPE = ["https://graph.microsoft.com/.default"]
    AUTHORITY = "https://login.microsoftonline.com/"+TENANT
    # AUTHORIZE_ENDPOINT = "/oauth2/v2.0/authorize"
    # TOKEN_ENDPOINT = "/oauth2/v2.0/token"
    # BASE_URI = "https://194.87.111.119:6000"
    # REQUEST_URI = "https://194.87.111.119:6000/token"
    BASE_URI = "https://d77702101852.ngrok.io"
    REQUEST_URI = "https://d77702101852.ngrok.io/token"
    # SYNC_URI = "http://194.87.111.119:5000"
    SYNC_URI = "http://localhost:5000"