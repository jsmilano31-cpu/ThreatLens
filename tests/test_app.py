import unittest
from unittest.mock import patch, Mock
import requests
from werkzeug.security import generate_password_hash
from app import create_app
from scanner import assess_url, scan_url, ScanError

class WebTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'test-only', 'USERNAME': 'analyst',
                               'PASSWORD_HASH': generate_password_hash('test-password')})
        self.client = self.app.test_client()

    def token(self):
        self.client.get('/login')
        with self.client.session_transaction() as session:
            return session['csrf']

    def login(self):
        return self.client.post('/login', data={'csrf': self.token(), 'username': 'analyst', 'password': 'test-password'})

    def test_login_logout_and_protected_dashboard(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        self.assertIn(b'Investigate a URL', self.client.get('/').data)
        with self.client.session_transaction() as session:
            token = session['csrf']
        self.assertEqual(self.client.post('/logout', data={'csrf': token}).status_code, 302)
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_wrong_password_and_csrf(self):
        self.assertEqual(self.client.post('/login', data={}).status_code, 400)
        response = self.client.post('/login', data={'csrf': self.token(), 'username': 'analyst', 'password': 'bad'})
        self.assertIn(b'incorrect', response.data)
        self.assertEqual(self.client.get('/').status_code, 302)

    @patch('app.scan_url')
    def test_scan_requires_login_and_consent(self, scan):
        self.login()
        with self.client.session_transaction() as session:
            token = session['csrf']
        self.client.post('/', data={'csrf': token, 'url': 'https://example.com'})
        scan.assert_not_called()
        scan.return_value = dict(url='https://example.com/', score=0, level='low', reasons=[], stats=None, notice='Local rules only')
        response = self.client.post('/', data={'csrf': token, 'url': 'https://example.com', 'consent': 'yes'})
        self.assertIn(b'Local rules only', response.data)
        scan.assert_called_once_with('https://example.com')

    def test_unconfigured_account(self):
        app = create_app({'TESTING': True, 'PASSWORD_HASH': None})
        client = app.test_client()
        self.assertIn(b'First-time setup', client.get('/login').data)

    @patch.dict('os.environ', {'VERCEL': '1', 'SECRET_KEY': 'stable-demo-secret'})
    def test_vercel_session_survives_separate_instances(self):
        config = {'TESTING': True, 'USERNAME': 'analyst',
                  'PASSWORD_HASH': generate_password_hash('test-password')}
        first = create_app(config).test_client()
        first.get('/login', base_url='https://demo.example')
        with first.session_transaction(base_url='https://demo.example') as session:
            token = session['csrf']
        response = first.post('/login', base_url='https://demo.example',
                              data={'csrf': token, 'username': 'analyst', 'password': 'test-password'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('Secure;', response.headers['Set-Cookie'])
        second = create_app(config).test_client()
        second.set_cookie('session', first.get_cookie('session', domain='demo.example').value,
                          domain='demo.example')
        self.assertIn(b'Investigate a URL', second.get('/', base_url='https://demo.example').data)

    @patch.dict('os.environ', {'VERCEL': '1'}, clear=True)
    def test_vercel_requires_shared_secret(self):
        with self.assertRaisesRegex(RuntimeError, 'SECRET_KEY'):
            create_app()

class ScannerTests(unittest.TestCase):
    def test_validation_and_case_preservation(self):
        self.assertEqual(assess_url('example.com/Case?Token=ABC')['url'], 'https://example.com/Case?Token=ABC')
        for value in ('', 'javascript://alert', 'https://', 'https://user:pass@example.com', 'https://example.com:bad', 'https://a b.com'):
            with self.subTest(value=value), self.assertRaises(ScanError):
                assess_url(value)

    def test_rules_and_shortener_boundaries(self):
        self.assertEqual(assess_url('http://bank123.example/login/verify/update/secure/account')['score'], 100)
        self.assertEqual(assess_url('https://notbit.ly.example')['score'], 0)
        self.assertEqual(assess_url('https://tinyurl.com/abc')['score'], 15)

    @patch.dict('os.environ', {}, clear=True)
    def test_no_key(self):
        result = scan_url('https://example.com')
        self.assertIsNone(result['stats'])
        self.assertIn('not configured', result['notice'])

    @patch('scanner.requests.request')
    def test_completed_analysis(self, request):
        submit = Mock()
        submit.json.return_value = {'data': {'id': 'abc'}}
        poll = Mock()
        poll.json.return_value = {'data': {'attributes': {'status': 'completed', 'stats': {'malicious': 2}}}}
        request.side_effect = [submit, poll]
        result = scan_url('https://example.com', api_key='test')
        self.assertEqual(result['stats']['malicious'], 2)
        self.assertEqual(request.call_args_list[0].kwargs['timeout'], 15)

    @patch('scanner.requests.request')
    def test_rate_limit_and_timeout_keep_local_score(self, request):
        response = Mock(status_code=429)
        request.side_effect = requests.HTTPError(response=response)
        self.assertIn('rate limit', scan_url('http://example.com', api_key='test')['notice'])
        request.side_effect = requests.Timeout()
        result = scan_url('http://example.com', api_key='test')
        self.assertEqual(result['score'], 20)
        self.assertIsNone(result['stats'])

    @patch('scanner.requests.request')
    def test_polling_is_bounded(self, request):
        request.return_value.json.return_value = {'data': {'id': 'abc'}}
        self.assertIn('pending', scan_url('https://example.com', api_key='test', max_wait=0)['notice'])
        self.assertEqual(request.call_count, 1)

if __name__ == '__main__':
    unittest.main()
