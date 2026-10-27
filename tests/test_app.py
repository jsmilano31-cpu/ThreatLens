import unittest
from unittest.mock import patch, Mock
import json
from html.parser import HTMLParser
import requests
from werkzeug.security import generate_password_hash
from app import EXAMPLES, create_app
from scanner import assess_url, scan_url, url_rep, ScanError


class ResultPayload(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.result = None
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get('id') == 'analysis-data':
            self.result = json.loads(attributes['data-analysis'])

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
        scan.return_value = dict(assess_url('https://example.com'), stats=None, notice='Local rules only',
                                 analysis_mode='virustotal', virustotal_status='not_configured')
        response = self.client.post('/', data={'csrf': token, 'url': 'https://example.com', 'consent': 'yes'})
        self.assertIn(b'Local rules only', response.data)
        scan.assert_called_once_with('https://example.com')

    def post_analysis(self, **data):
        with self.client.session_transaction() as session:
            token = session['csrf']
        return self.client.post('/', data=dict(csrf=token, **data))

    @patch.dict('os.environ', {'VT_API_KEY': 'configured-test-key'})
    @patch('scanner.requests.request')
    def test_examples_are_local_even_with_key(self, request):
        self.login()
        for example, expected in zip(EXAMPLES, (0, 40, 100)):
            with self.subTest(example=example['id']):
                response = self.post_analysis(action='example', example=example['id'])
                self.assertEqual(response.status_code, 200)
                result = ResultPayload(response.get_data(as_text=True)).result
                self.assertEqual(result['score'], expected)
                self.assertEqual(result['url'], example['url'])
                self.assertEqual(result['analysis_mode'], 'demo')
                self.assertEqual(result['virustotal_status'], 'not_requested')
                self.assertIsNone(result['stats'])
        request.assert_not_called()

    @patch('scanner.requests.request')
    def test_local_mode_and_unknown_actions(self, request):
        self.login()
        response = self.post_analysis(action='local', url='http://shop.example/login')
        result = ResultPayload(response.get_data(as_text=True)).result
        self.assertEqual(result['score'], 30)
        self.assertEqual(result['analysis_mode'], 'local')
        self.assertIn(b'URL anatomy', response.data)
        self.assertIn(b'What changes the score?', response.data)
        self.assertIn(b'ORIGINAL CUSTOM SCORE', response.data)
        for data in ({'action': 'example', 'example': 'invalid'}, {'action': 'unknown'},
                     {'action': 'local', 'url': 'https://'}):
            response = self.post_analysis(**data)
            self.assertIn(b'role="alert"', response.data)
            self.assertIsNone(ResultPayload(response.get_data(as_text=True)).result)
        request.assert_not_called()

    def test_examples_and_local_analysis_require_auth_and_csrf(self):
        token = self.token()
        self.assertEqual(self.client.post('/', data={'csrf': token, 'action': 'example', 'example': 'high'}).status_code, 302)
        self.login()
        self.assertEqual(self.client.post('/', data={'action': 'local', 'url': 'https://demo.example'}).status_code, 400)

    def test_untrusted_url_is_text_and_safe_json(self):
        self.login()
        url = 'https://café.example:8443/<script>alert(1)</script>?q="<img/src=x/onerror=alert(1)>"&verify=yes'
        response = self.post_analysis(action='local', url=url)
        markup = response.get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', markup)
        self.assertNotIn('<img/src=x/onerror=alert(1)>', markup)
        self.assertIn('&lt;script&gt;', markup)
        self.assertNotIn("'unsafe-inline'", response.headers['Content-Security-Policy'])
        result = ResultPayload(markup).result
        self.assertEqual(result['url'], url)
        self.assertEqual(result['components']['hostname'], 'café.example')
        self.assertEqual(result['components']['port'], 8443)

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
    def test_components_and_stable_rules(self):
        result = assess_url('http://Bank123.example:8080/Case/login?verify=Yes')
        self.assertEqual(result['components'], dict(protocol='http', hostname='bank123.example',
                          port=8080, path='/Case/login', query='verify=Yes'))
        rules = {reason['id']: reason for reason in result['reasons']}
        self.assertEqual(rules['http']['components'], ['protocol'])
        self.assertEqual(rules['keyword_login']['components'], ['path'])
        self.assertEqual(rules['keyword_verify']['components'], ['query'])
        self.assertEqual(rules['keyword_bank']['components'], ['hostname'])
        self.assertEqual(rules['numeric_hostname']['components'], ['hostname'])
        self.assertEqual(len(rules), len(result['reasons']))
        self.assertEqual(url_rep(result['url']), result['score'])
        self.assertTrue(result['analyzed_at'].endswith('+00:00'))
        self.assertIsNone(assess_url('https://demo.example')['components']['port'])

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
