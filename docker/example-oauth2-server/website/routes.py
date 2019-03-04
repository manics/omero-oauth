from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
from authlib.flask.oauth2 import current_token
from authlib.specs.rfc6749 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth


bp = Blueprint(__name__, 'home')


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username, email=email)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)


@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if request.form['confirm']:
        grant_user = user
    else:
        grant_user = None
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username, email=user.email)


@bp.route('/api/create_test_client', methods=('POST',))
def create_test_client():
    print('args {}'.format(request.args))
    if not OAuth2Client.query.filter_by(client_name='omero').first():
        client = OAuth2Client(
            client_name='Oauth Test Client',
            client_uri='http://localhost',
            scope='profile',
            redirect_uri=request.json['redirect_uri'],
            grant_type='authorization_code',
            response_type='code',
            token_endpoint_auth_method='client_secret_basic',
            client_id=request.json['client_id'],
            client_secret=request.json['client_secret'],
        )
        db.session.add(client)
        db.session.commit()
    return jsonify(client_id='CLIENT_ID', client_secret='CLIENT_SECRET')
