import os
import requests
import uuid
import msal
import app_config

from flask import Flask, session, redirect, request, url_for, render_template
from flask_session import FileSystemSessionInterface
from itsdangerous import want_bytes


app = Flask(__name__)
app.config.from_object(app_config)

# from werkzeug.middleware.proxy_fix import ProxyFix
# app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)


class CustomFileSystemSessionInterface(FileSystemSessionInterface):
    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        if not session:
            if session.modified:
                self.cache.delete(self.key_prefix + session.sid)
                response.delete_cookie(app.session_cookie_name,
                                       domain=domain, path=path)
            return

        expires = self.get_expiration_time(app, session)
        data = dict(session)
        self.cache.set(self.key_prefix + session.sid, data,
                       _total_seconds(app.permanent_session_lifetime))
        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session.sid))
        else:
            session_id = session.sid
        sam_site = 'None'
        response.headers.add('Set-Cookie', '{0}={1}; Expires={2}; SameSite={3}; Secure; HttpOnly; Path=/'
                             .format(app.session_cookie_name, session_id, expires, sam_site))


# Default initialization values from library
app.session_interface = CustomFileSystemSessionInterface(
    cache_dir=os.path.join(os.getcwd(), 'flask_session'), threshold=500, mode=384,
    key_prefix='session:', use_signer=False, permanent=True
)


@app.route('/')
def index():
    if not session.get("user"):
        return render_template("auth.html", base_uri=app_config.BASE_URI)

    assignments = _get_assignments()
    if not assignments:
        return render_template("auth.html", base_uri=app_config.BASE_URI)

    # print(assignments['value'][3])
    return render_template("index.html", base_uri=app_config.BASE_URI,
                           assignments=assignments['value'])


@app.route('/config')
def config():
    return render_template('config.html', base_uri=app_config.BASE_URI)


@app.route('/login')
def login():
    session["state"] = str(uuid.uuid4())
    msal_app = _build_msal_app()
    auth_url = msal_app.get_authorization_request_url(
        scopes=app_config.SCOPE,
        state=session["state"],
        redirect_uri=app_config.REQUEST_URI)
    return redirect(auth_url)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route('/token')
def get_token():
    if request.args['state'] != session.get("state"):
        return render_template("failure.html", reason="StateDoesNotMatch")

    cache = _load_cache()
    msal_app = _build_msal_app(cache)
    result = msal_app.acquire_token_by_authorization_code(
        code=request.args['code'],
        scopes=app_config.SCOPE,
        redirect_uri=app_config.REQUEST_URI)

    if "error" in result:
        return render_template("failure.html", reason="%s %s".format(result["error"], result.get("error_description")))

    session["user"] = result.get("id_token_claims")
    _save_cache(cache)
    return render_template("success.html")


@app.route('/context', methods=['POST'])
def get_context():
    if not session.get("user"):
        return None
        # return redirect(url_for("index"))
    group_id = request.form["group_id"]
    session["group_id"] = group_id
    print("***Group ID: " + str(group_id))
    return group_id


@app.route('/sync', methods=['POST'])
def synchronize_assignents():
    if not session.get('user'):
        return None

     

    return "success", 200

# @app.route('/graph')
# def graph_call():
#     token = _get_token_from_cache(app_config.SCOPE)
#     if not token:
#         return redirect(url_for('index'))
#     graph_data = requests.get(
#         'https://graph.microsoft.com/beta/education/classes',
#         headers={'Authorization': 'Bearer ' + token['access_token']},
#     ).json()
#     print(graph_data)
#     return redirect(url_for('index'))
#

# @app.route('/assignments')
# def get_assignments():
#     token = _get_token_from_cache(app_config.SCOPE)
#     if not token:
#         return redirect(url_for('index'))
#     url_query = "https://graph.microsoft.com/beta/education/classes/" + \
#                 session['group_id'] + \
#                 "/assignments"
#     data = requests.get(
#         url_query,
#         headers={'Authorization': 'Bearer ' + token['access_token']},
#     ).json()
#     print(data)
#     return redirect(url_for('index'))


# @app.route('/getcontext')
# def context_call():
#     return render_template('context.html')
#

def _get_assignments():
    token = _get_token_from_cache(app_config.SCOPE)
    group_id = session.get("group_id")
    # print("Token: {0},\nGroupID: {1}".format(token, group_id))
    if not token or not group_id:
        return None
    url_query = "https://graph.microsoft.com" + \
                "/beta/education/classes/" + \
                group_id + \
                "/assignments"
    assignments = requests.get(
        url_query,
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()
    return assignments


def _build_msal_app(cache=None) -> msal.ConfidentialClientApplication:
    msal_app = msal.ConfidentialClientApplication(
        client_id=app_config.CLIENT_ID,
        authority=app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET,
        token_cache=cache)
    return msal_app


def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache: msal.SerializableTokenCache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _get_token_from_cache(scope=None):
    cache = _load_cache()
    cca = _build_msal_app(cache)
    accounts = cca.get_accounts()
    if accounts:
        result = cca.acquire_token_silent(
            scopes=scope,
            account=accounts[0])
        _save_cache(cache)
        return result


def _total_seconds(td):
    return td.days * 60 * 60 * 24 + td.seconds


if __name__ == '__main__':
    app.run(port=9000)
