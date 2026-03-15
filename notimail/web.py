"""
Flask web interface for NotiMail.

Provides the login page, dashboard, REST API endpoints, and session
management. Uses flask-wtf for CSRF protection on web forms.
"""

import functools
import hashlib
import json
import logging
from typing import Any, Callable, Dict, Optional

from flask import (
    Flask, Blueprint, request, jsonify, redirect, url_for,
    session, render_template, flash, g,
)

from notimail.auth import (
    check_password, hash_password, generate_api_key, validate_api_key,
    create_invite, redeem_invite, RateLimiter,
)
from notimail.crypto import CryptoManager
from notimail.database import DatabaseHandler


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f: Callable) -> Callable:
    """Decorator that requires an active web session (cookie-based login)."""
    @functools.wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('web.login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f: Callable) -> Callable:
    """Decorator that requires the logged-in user to be an admin."""
    @functools.wraps(f)
    @login_required
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if session.get('role') != 'admin':
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required.', 'error')
            return redirect(url_for('web.dashboard'))
        return f(*args, **kwargs)
    return decorated


def api_key_required(f: Callable) -> Callable:
    """Decorator that requires a valid API key via Authorization: Bearer header."""
    @functools.wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401

        raw_key = auth_header[7:]  # Strip "Bearer "
        db: DatabaseHandler = g.db
        rate_limiter: RateLimiter = g.rate_limiter

        # Check rate limiting for API key failures
        ip = request.remote_addr
        if rate_limiter.is_locked_out(ip):
            return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429

        key_record = validate_api_key(raw_key, db)
        if key_record is None:
            # Record failure with a generic HMAC to avoid leaking key info
            rate_limiter.record_failure(ip, 'api-key-attempt', username_exists=False)
            return jsonify({'error': 'Invalid API key'}), 401

        g.api_user_id = key_record['user_id']
        g.api_key_id = key_record['id']
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Blueprint: web routes (HTML pages)
# ---------------------------------------------------------------------------

web_bp = Blueprint('web', __name__)


@web_bp.route('/health')
def health():
    """Unauthenticated health check for container/systemd probes."""
    return jsonify({'status': 'OK'}), 200


@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with username/password form."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    rate_limiter: RateLimiter = g.rate_limiter
    ip = request.remote_addr

    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('web.dashboard'))
        return render_template('login.html')

    # POST — process login
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if rate_limiter.is_locked_out(ip):
        flash('Too many failed attempts. Please try again later.', 'error')
        return render_template('login.html'), 429

    username_hmac = crypto.hmac_hash(username)
    user = db.get_user_by_lookup(username_hmac)

    if user is None:
        # Username doesn't exist — record for enumeration detection
        lockout_msg = rate_limiter.record_failure(ip, username_hmac, username_exists=False)
        # Always show generic error to avoid leaking username existence
        flash('Invalid credentials.', 'error')
        return render_template('login.html'), 401

    if not check_password(password, user['password_hash']):
        lockout_msg = rate_limiter.record_failure(ip, username_hmac, username_exists=True)
        flash('Invalid credentials.', 'error')
        return render_template('login.html'), 401

    # Success
    rate_limiter.record_success(ip, username_hmac)
    session['user_id'] = user['id']
    session['role'] = user['role']
    session['username'] = crypto.decrypt(user['username'])
    session.permanent = True
    db.update_user_last_login(user['id'])

    logging.info(f"User logged in: {session['username']} (id={user['id']})")
    return redirect(url_for('web.dashboard'))


@web_bp.route('/logout')
def logout():
    """Clear the session and redirect to login."""
    username = session.get('username', 'unknown')
    session.clear()
    logging.info(f"User logged out: {username}")
    return redirect(url_for('web.login'))


@web_bp.route('/')
@login_required
def dashboard():
    """Main dashboard page."""
    return render_template('dashboard.html', username=session.get('username'))


@web_bp.route('/register/<code>', methods=['GET', 'POST'])
def register(code: str):
    """Registration page for new users via invite code."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto

    # Verify the invite is valid before showing the form
    invite = db.get_invite_by_code(code)
    if invite is None or invite['redeemed_by'] is not None:
        flash('Invalid or already used invite code.', 'error')
        return render_template('register.html', valid=False), 400

    import datetime
    if invite['expires_at']:
        expires = datetime.datetime.strptime(invite['expires_at'], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.now() > expires:
            flash('This invite code has expired.', 'error')
            return render_template('register.html', valid=False), 400

    if request.method == 'GET':
        return render_template('register.html', valid=True, code=code)

    # POST — create user
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    password_confirm = request.form.get('password_confirm', '')

    if not username:
        flash('Username is required.', 'error')
        return render_template('register.html', valid=True, code=code)
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return render_template('register.html', valid=True, code=code)
    if password != password_confirm:
        flash('Passwords do not match.', 'error')
        return render_template('register.html', valid=True, code=code)

    # Check if username already exists
    if db.get_user_by_lookup(crypto.hmac_hash(username)):
        flash('Username already taken.', 'error')
        return render_template('register.html', valid=True, code=code)

    user_id = redeem_invite(db, crypto, code, username, password)
    if user_id is None:
        flash('Failed to create account. Invite may be invalid.', 'error')
        return render_template('register.html', valid=True, code=code)

    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('web.login'))


# ---------------------------------------------------------------------------
# Blueprint: API routes (JSON)
# ---------------------------------------------------------------------------

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/accounts', methods=['GET'])
@api_key_required
def list_accounts():
    """List the authenticated user's email accounts."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    accounts = db.get_email_accounts_for_user(g.api_user_id)
    result = []
    for acct in accounts:
        try:
            result.append({
                'id': acct['id'],
                'account_name': acct['account_name'],
                'email_user': crypto.decrypt(acct['email_user_encrypted']),
                'host': crypto.decrypt(acct['host_encrypted']),
                'port': acct['port'],
                'folders': acct['folders'],
                'enabled': bool(acct['enabled']),
            })
        except Exception:
            result.append({
                'id': acct['id'],
                'account_name': acct['account_name'],
                'error': 'Failed to decrypt',
            })
    return jsonify(result)


@api_bp.route('/accounts', methods=['POST'])
@api_key_required
def create_account():
    """Create a new email account with optional notification config."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    required = ['account_name', 'email_user', 'email_pass', 'host']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Missing required field: {field}'}), 400

    # Check host limit warnings
    warning = None
    if g.host_limits:
        warning = g.host_limits.check_limit_warning(data['host'], 1)

    account_id = db.add_email_account(
        user_id=g.api_user_id,
        account_name=data['account_name'],
        email_user_encrypted=crypto.encrypt(data['email_user']),
        email_pass_encrypted=crypto.encrypt(data['email_pass']),
        host_encrypted=crypto.encrypt(data['host']),
        port=data.get('port', 993),
        folders=data.get('folders', 'inbox'),
    )

    # Add notification configs if provided
    notifications = data.get('notifications', [])
    for notif in notifications:
        provider_type = notif.get('provider_type', '')
        notif_config = notif.get('config', {})
        if provider_type and notif_config:
            db.add_notification_config(
                email_account_id=account_id,
                provider_type=provider_type,
                config_encrypted=crypto.encrypt(json.dumps(notif_config)),
            )

    result = {'id': account_id, 'status': 'created'}
    if warning:
        result['warning'] = warning
    return jsonify(result), 201


@api_bp.route('/accounts/<int:account_id>', methods=['GET'])
@api_key_required
def get_account(account_id: int):
    """Get details of a specific email account."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404
    return jsonify({
        'id': acct['id'],
        'account_name': acct['account_name'],
        'email_user': crypto.decrypt(acct['email_user_encrypted']),
        'host': crypto.decrypt(acct['host_encrypted']),
        'port': acct['port'],
        'folders': acct['folders'],
        'enabled': bool(acct['enabled']),
    })


@api_bp.route('/accounts/<int:account_id>', methods=['PUT'])
@api_key_required
def update_account(account_id: int):
    """Update an email account."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    updates = {}
    if 'email_user' in data:
        updates['email_user_encrypted'] = crypto.encrypt(data['email_user'])
    if 'email_pass' in data:
        updates['email_pass_encrypted'] = crypto.encrypt(data['email_pass'])
    if 'host' in data:
        updates['host_encrypted'] = crypto.encrypt(data['host'])
    if 'port' in data:
        updates['port'] = data['port']
    if 'folders' in data:
        updates['folders'] = data['folders']
    if 'enabled' in data:
        updates['enabled'] = 1 if data['enabled'] else 0

    if updates:
        db.update_email_account(account_id, **updates)

    return jsonify({'status': 'updated'})


@api_bp.route('/accounts/<int:account_id>', methods=['DELETE'])
@api_key_required
def delete_account(account_id: int):
    """Delete an email account and its notification configs."""
    db: DatabaseHandler = g.db
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404
    db.delete_email_account(account_id)
    return jsonify({'status': 'deleted'})


@api_bp.route('/accounts/<int:account_id>/notifications', methods=['GET'])
@api_key_required
def list_notifications(account_id: int):
    """List notification configs for an email account."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404

    configs = db.get_notification_configs_for_account(account_id)
    result = []
    for cfg in configs:
        try:
            result.append({
                'id': cfg['id'],
                'provider_type': cfg['provider_type'],
                'config': json.loads(crypto.decrypt(cfg['config_encrypted'])),
            })
        except Exception:
            result.append({'id': cfg['id'], 'provider_type': cfg['provider_type'], 'error': 'decrypt failed'})
    return jsonify(result)


@api_bp.route('/accounts/<int:account_id>/notifications', methods=['POST'])
@api_key_required
def add_notification(account_id: int):
    """Add a notification config to an email account."""
    db: DatabaseHandler = g.db
    crypto: CryptoManager = g.crypto
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404

    data = request.get_json()
    if not data or not data.get('provider_type') or not data.get('config'):
        return jsonify({'error': 'provider_type and config required'}), 400

    config_id = db.add_notification_config(
        email_account_id=account_id,
        provider_type=data['provider_type'],
        config_encrypted=crypto.encrypt(json.dumps(data['config'])),
    )
    return jsonify({'id': config_id, 'status': 'created'}), 201


@api_bp.route('/accounts/<int:account_id>/notifications/<int:config_id>', methods=['DELETE'])
@api_key_required
def delete_notification(account_id: int, config_id: int):
    """Delete a notification config."""
    db: DatabaseHandler = g.db
    acct = db.get_email_account_by_id(account_id)
    if not acct or acct['user_id'] != g.api_user_id:
        return jsonify({'error': 'Account not found'}), 404
    db.delete_notification_config(config_id)
    return jsonify({'status': 'deleted'})


@api_bp.route('/keys', methods=['POST'])
@api_key_required
def create_key():
    """Generate a new API key for the authenticated user."""
    db: DatabaseHandler = g.db
    data = request.get_json() or {}
    label = data.get('label', '')

    raw_key, key_hash, key_prefix = generate_api_key()
    db.add_api_key(g.api_user_id, key_hash, key_prefix, label)
    # Raw key is shown only once
    return jsonify({'key': raw_key, 'prefix': key_prefix, 'label': label}), 201


@api_bp.route('/keys', methods=['GET'])
@api_key_required
def list_keys():
    """List API keys for the authenticated user (prefix and label only)."""
    db: DatabaseHandler = g.db
    keys = db.get_api_keys_for_user(g.api_user_id)
    return jsonify([{
        'id': k['id'], 'prefix': k['key_prefix'], 'label': k['label'],
        'created_at': k['created_at'], 'last_used': k['last_used'],
        'revoked': bool(k['revoked']),
    } for k in keys])


@api_bp.route('/keys/<int:key_id>', methods=['DELETE'])
@api_key_required
def revoke_key(key_id: int):
    """Revoke an API key."""
    db: DatabaseHandler = g.db
    if db.revoke_api_key(key_id, g.api_user_id):
        return jsonify({'status': 'revoked'})
    return jsonify({'error': 'Key not found'}), 404


@api_bp.route('/invites', methods=['POST'])
@api_key_required
def create_invite_api():
    """Generate an invite code."""
    db: DatabaseHandler = g.db
    expire_days = 7  # Could read from config
    code = create_invite(db, g.api_user_id, expire_days)
    return jsonify({'code': code, 'expires_days': expire_days}), 201


@api_bp.route('/invites', methods=['GET'])
@api_key_required
def list_invites():
    """List invites created by the authenticated user."""
    db: DatabaseHandler = g.db
    invites = db.get_invites_for_user(g.api_user_id)
    return jsonify([{
        'id': i['id'], 'code': i['code'],
        'redeemed': i['redeemed_by'] is not None,
        'created_at': i['created_at'], 'expires_at': i['expires_at'],
    } for i in invites])


@api_bp.route('/status', methods=['GET'])
@api_key_required
def api_status():
    """Get connection status for the authenticated user's accounts."""
    multi_handler = g.get('multi_handler')
    if not multi_handler:
        return jsonify({'error': 'IMAP handlers not available'}), 503

    db: DatabaseHandler = g.db
    accounts = db.get_email_accounts_for_user(g.api_user_id)
    account_ids = {a['id'] for a in accounts}

    status_info = []
    for handler in multi_handler.handlers:
        status_info.append({
            'email_user': handler.email_user,
            'folder': handler.folder,
            'connected': handler.mail is not None,
            'last_check': handler.last_check.strftime("%Y-%m-%d %H:%M:%S") if handler.last_check else None,
            'last_error': handler.last_error,
            'retry_count': handler.retry_count,
        })
    return jsonify(status_info)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    db: DatabaseHandler,
    crypto: CryptoManager,
    config: dict,
    rate_limiter: Optional[RateLimiter] = None,
    multi_handler: Any = None,
    host_limits: Any = None,
) -> Flask:
    """Create and configure the Flask application.

    Args:
        db: The DatabaseHandler instance.
        crypto: The CryptoManager instance.
        config: Dict-like config (ConfigParser or dict) with GENERAL settings.
        rate_limiter: Optional RateLimiter instance. Created with defaults if None.
        multi_handler: The MultiIMAPHandler instance (may be None at startup).
        host_limits: Optional HostLimitManager for connection limit warnings.

    Returns:
        A configured Flask application.
    """
    import datetime as dt

    app = Flask(
        __name__,
        template_folder='templates',
    )

    # Session configuration
    app.secret_key = config.get('GENERAL', 'FlaskSecretKey', fallback=None)
    if not app.secret_key:
        app.secret_key = crypto.flask_secret_key
    session_hours = int(config.get('GENERAL', 'SessionLifetimeHours', fallback='24'))
    app.permanent_session_lifetime = dt.timedelta(hours=session_hours)

    if rate_limiter is None:
        rate_limiter = RateLimiter(
            max_attempts=int(config.get('GENERAL', 'RateLimitMaxAttempts', fallback='5')),
            window_minutes=int(config.get('GENERAL', 'RateLimitWindowMinutes', fallback='15')),
            lockout_minutes=int(config.get('GENERAL', 'RateLimitLockoutMinutes', fallback='30')),
        )

    # ProxyFix for reverse proxy support
    trusted_proxies = config.get('GENERAL', 'TrustedProxies', fallback='')
    if trusted_proxies.strip():
        from werkzeug.middleware.proxy_fix import ProxyFix
        num_proxies = int(trusted_proxies.strip())
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=num_proxies, x_proto=num_proxies)

    # CSRF protection via flask-wtf
    try:
        from flask_wtf.csrf import CSRFProtect
        csrf = CSRFProtect(app)
        # Exempt API blueprint from CSRF (it uses Bearer token auth)
        csrf.exempt(api_bp)
    except ImportError:
        logging.warning("flask-wtf not installed. CSRF protection disabled.")

    # Inject shared objects into Flask's g context for each request
    @app.before_request
    def inject_context():
        g.db = db
        g.crypto = crypto
        g.rate_limiter = rate_limiter
        g.multi_handler = multi_handler
        g.host_limits = host_limits

    # Register blueprints
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    return app
