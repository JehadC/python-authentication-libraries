import os
import pathlib
import requests
import google.auth.transport.requests
from flask import Flask, abort, redirect, render_template, request, session, url_for
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

# Disable insecure transport warning
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Create a Flask app instance
app = Flask(__name__)
app.secret_key = 'SECRET-KEY'

# Define location of client secrets file
CLIENT_SECRETS_FILE = os.path.join(
    pathlib.Path(__file__).parent,
    'client_secret_file.json'
)

# Define the scopes for the flow object
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

# Define the redirect URI for the flow object
REDIRECT_URI = 'http://127.0.0.1:5000/callback'

# Initialize the Google OAuth2 flow
google_oauth2_flow = Flow.from_client_secrets_file(
    client_secrets_file = CLIENT_SECRETS_FILE,
    scopes = SCOPES,
    redirect_uri = REDIRECT_URI
)


# Define a root route.
@app.route('/')
def index():
    return redirect(url_for('login'))


# Define a route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('authorization'))
    return render_template('login.html')


# Define a route for authorization
@app.route('/authorization')
def authorization():
    authorization_url, state = google_oauth2_flow.authorization_url(
        prompt='consent')
    session['state'] = state
    return redirect(authorization_url)


# Define a route for callback
@app.route("/callback")
def callback():
    google_oauth2_flow.fetch_token(authorization_response=request.url)
    if not session['state'] == request.args['state']:
        abort(500)
    credentials = google_oauth2_flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(
        session=cached_session)
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=credentials.client_id
    )
    session['google_id'] = id_info.get('sub')
    session['name'] = id_info.get('name')
    return redirect('/dashboard')


# Define a route for dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# Define a route for logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# Start the Flask app if the script is run directly
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
