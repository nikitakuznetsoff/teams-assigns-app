import os
import requests
import uuid
import msal
import config

from flask import Flask, session, redirect, request, url_for, render_template
from flask_session import FileSystemSessionInterface
from itsdangerous import want_bytes


app = Flask(__name__)
app.config.from_object(config.FlaskConfig)
app_config = config.AppConfig()

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


# Initialization with default values from library
app.session_interface = CustomFileSystemSessionInterface(
    cache_dir=os.path.join(os.getcwd(), 'flask_session'), threshold=500, mode=384,
    key_prefix='session:', use_signer=False, permanent=True
)


@app.route('/')
def index():
    if not session.get("user"):
        return render_template("auth.html", base_uri=app_config.BASE_URI)

    token = _get_token_from_cache(app_config.SCOPE)
    group_id = session.get("group_id")
    
    if not token or not group_id:
        return render_template("auth.html", base_uri=app_config.BASE_URI)

    assignments = get_assignments(token, group_id)    
    for v in preprocessing_assignments(assignments['value']):
        print("{0}\n".format(v))


    # subm1 = get_submissions(token, group_id, assignments['value'][0]['id'])['value']
    # print(subm1)
    # print()
    # subm2 = get_submissions(token, group_id, assignments['value'][1]['id'])['value']
    # print(subm2)
    # print()
    # subm3 = get_submissions(token, group_id, assignments['value'][2]['id'])['value']
    # print(subm3)
    # print()

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
    return group_id


@app.route('/sync')
def synchronize_assignments():
    if not session.get('user'):
        return redirect(url_for('index'))

    group_id = session.get("group_id")
    token = _get_token_from_cache(app_config.SCOPE)
    if not token or not group_id:
        return redirect(url_for('index'))

    assignments = _get_assignments(token, group_id)['value']
    if not assignments:
        return redirect(url_for('index'))
    
    assignments_pp = preprocessing_assignments(assignments)
    for assign in assignments_pp:
        submissions = get_submissions(token, group_id, assign['id'])['value']
        if susbmissions:
          submissions_pp = preprocessing_submissions(submissions)
        else:
            submissions_pp = []
        assign['submissions'] = submissions_pp
    print(assignments)
    r = requests.post(
        app_config.SYNC_URI,
        data={'assignments': assignments_pp, 'class_id': group_id}
    )
    if r.ok:
        return render_template('sync_success.html', base_uri=app_config.BASE_URI)
    else:
        return render_template('sync_failure.html', base_uri=app_config.BASE_URI)


def get_members(token=None, group_id=None):
    # group_id = session.get("group_id")
    if not token or not group_id:
        return None
    url_query = "https://graph.microsoft.com" + \
                "/beta/education/classes/" + \
                group_id + \
                "/members"
    members = requests.get(
        url_query,
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()
    return members


def get_assignments(token=None, group_id=None):
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

# GET /education/classes/{id}/assignments/{id}/submissions/
def get_submissions(token=None, group_id=None, assignment_id=None):
    if not token or not group_id or not assignment_id:
        return None
    url_query = "https://graph.microsoft.com" + \
                "/beta/education/classes/" + group_id + \
                "/assignments/" + assignment_id + \
                "/submissions"
    submissions = requests.get(
        url_query,
        headers={'Authorization': 'Bearer ' + token['access_token']},
    ).json()
    return submissions


def preprocessing_assignments(assignments):
    result = [
        {
            'id': assign['id'],
            'displayName': assign['displayName'],
            'dueDateTime': assign['dueDateTime'],
            'assignedDateTime': assign['assignedDateTime'],
            'status': assign['status'],
            'grading': assign['grading'],
        } for assign in assignments]
    return result


def preprocessing_submissions(submissions):
    result = [
        {
            'id': sub['id'],
            'status': sub['status'],
            'userId': sub['recipient']['userId']
        } for sub in submission]
    return result


def preprocessing_members(members):
    result = [
        {
            'id': member['id'],
            'userPrincipalName': member['userPrincipalName'],
            'userType': member['userType']
        } for member in members]
    return result 


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
    # app.run(host='0.0.0.0')
