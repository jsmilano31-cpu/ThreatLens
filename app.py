"""Database-free local ThreatLens v1 application."""
import hmac
import os
import secrets
from datetime import timedelta
from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from scanner import ScanError, scan_url

def create_app(test_config=None):
    app = Flask(__name__, static_folder='public/static', static_url_path='/static')
    password = os.environ.get('THREATLENS_PASSWORD')
    on_vercel = os.environ.get('VERCEL') == '1'
    secret = os.environ.get('SECRET_KEY')
    if on_vercel and not secret:
        raise RuntimeError('Set SECRET_KEY in Vercel environment variables before deploying.')
    app.config.update(SECRET_KEY=secret or secrets.token_hex(32),
        USERNAME=os.environ.get('THREATLENS_USERNAME', 'analyst'),
        PASSWORD_HASH=generate_password_hash(password) if password else None,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=on_vercel or os.environ.get('COOKIE_SECURE') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2), MAX_CONTENT_LENGTH=16384)
    if test_config:
        app.config.update(test_config)

    @app.before_request
    def protect_forms():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(32)
        if request.method == 'POST' and not hmac.compare_digest(session['csrf'], request.form.get('csrf', '')):
            abort(400, 'Session expired. Refresh the page and try again.')

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'"
        return response

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if session.get('user'):
            return redirect(url_for('dashboard'))
        error = None
        configured = bool(app.config['PASSWORD_HASH'])
        if request.method == 'POST':
            if not configured:
                error = 'Set THREATLENS_PASSWORD on the server to enable login.'
            else:
                valid_password = check_password_hash(app.config['PASSWORD_HASH'], request.form.get('password', ''))
                if hmac.compare_digest(request.form.get('username', '').encode(), app.config['USERNAME'].encode()) and valid_password:
                    session.clear()
                    session.update(user=app.config['USERNAME'], csrf=secrets.token_hex(32))
                    session.permanent = True
                    return redirect(url_for('dashboard'))
                error = 'Username or password is incorrect.'
        return render_template('login.html', error=error, configured=configured)

    @app.route('/', methods=['GET', 'POST'])
    def dashboard():
        if not session.get('user'):
            return redirect(url_for('login'))
        result, error, value = None, None, ''
        if request.method == 'POST':
            value = request.form.get('url', '')
            if request.form.get('consent') != 'yes':
                error = 'Confirm that this URL may be submitted to VirusTotal.'
            else:
                try:
                    result = scan_url(value)
                except ScanError as exc:
                    error = str(exc)
        return render_template('dashboard.html', result=result, error=error, value=value)

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))
    return app

# Vercel discovers this module-level WSGI application.
app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
