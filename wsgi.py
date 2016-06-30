import os
from flask import Flask
from rauth.service import OAuth2Service

application = Flask(__name__)

github = OAuth2Service(
    name='github',
    base_url='https://api.github.com/',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    client_id= os.environ.get('GITHUB_CLIENT_ID'),
    client_secret= os.environ.get('GITHUB_CLIENT_SECRET'),
)

@application.route("/")
def index():
    return render_template('login.html')

@application.route('/about')
def about():
    if session.has_key('token'):
        auth = github.get_session(token = session['token'])
        resp = auth.get('/user')
        if resp.status_code == 200:
            user = resp.json()

        return render_template('about.html', user = user)
    else:
        return redirect(url_for('login'))


@application.route('/login')
def login():
    redirect_uri = url_for('authorized', next=request.args.get('next') or 
        request.referrer or None, _external=True)
    print(redirect_uri)
    # More scopes http://developer.github.com/v3/oauth/#scopes
    params = {'redirect_uri': redirect_uri, 'scope': 'user:email'} 
    print(github.get_authorize_url(**params))
    return redirect(github.get_authorize_url(**params))

@application.route('/github/callback')
def authorized():
    # check to make sure the user authorized the request
    if not 'code' in request.args:
        flash('You did not authorize the request')
        return redirect(url_for('index'))

    # make a request for the access token credentials using code
    redirect_uri = url_for('authorized', _external=True)

    data = dict(code=request.args['code'],
        redirect_uri=redirect_uri,
        scope='user:email,public_repo')

    auth = github.get_auth_session(data=data)

    # the "me" response
    me = auth.get('user').json()

    session['token'] = auth.access_token

    flash('Logged in as ' + me['name'])
    return redirect(url_for('index'))

if __name__ == "__main__":
    application.run()
