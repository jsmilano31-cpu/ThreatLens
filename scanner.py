"""Shared URL scoring and VirusTotal scanner for CLI and web."""
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
import requests

class ScanError(ValueError):
    pass

def assess_url(value):
    value = value.strip()
    if not value or len(value) > 4096 or any(c.isspace() or ord(c) < 32 for c in value):
        raise ScanError('Enter a URL without spaces, up to 4096 characters.')
    if '://' not in value:
        value = 'https://' + value
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
        if parts.scheme not in ('http', 'https') or not host:
            raise ValueError()
        host.encode('idna')
        if parts.username is not None or parts.password is not None:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ScanError('Enter a valid HTTP or HTTPS URL without embedded credentials.')
    url = urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))
    host = host.lower()
    components = dict(protocol=parts.scheme, hostname=host, port=port,
                      path=parts.path or '/', query=parts.query)
    reasons = []

    def signal(rule_id, label, points, explanation, affected):
        reasons.append(dict(id=rule_id, label=label, points=points,
                            explanation=explanation, components=affected))

    if parts.scheme != 'https':
        signal('http', 'Connection uses HTTP instead of HTTPS', 20,
               'HTTP does not encrypt the connection. HTTPS alone would not prove a site is trustworthy.', ['protocol'])
    for word in ('login', 'verify', 'update', 'secure', 'account', 'bank'):
        if word in url.lower():
            affected = [name for name, value in components.items() if word in str(value or '').lower()]
            signal('keyword_' + word, f"URL contains '{word}'", 10,
                   'Account-related wording can appear in phishing lures and legitimate websites. Check the context.', affected)
    if any(host == s or host.endswith('.' + s) for s in ('bit.ly', 'tinyurl.com', 'tinyurl', 't.co', 'is.gd')):
        signal('shortener', 'Known URL shortening service', 15,
               'A shortened link hides its eventual destination. This scanner does not follow redirects.', ['hostname'])
    if len(url) > 75:
        signal('long_url', 'URL is longer than 75 characters', 10,
               'Long URLs can obscure important details, but legitimate links can also be long.',
               [name for name, value in components.items() if value is not None and value != ''])
    if any(c.isdigit() for c in host):
        signal('numeric_hostname', 'Hostname contains numbers', 25,
               'Numbers can be used in lookalike names or address-based URLs. They are also common in legitimate domains.', ['hostname'])
    score = min(sum(reason['points'] for reason in reasons), 100)
    return dict(url=url, score=score, level='high' if score >= 70 else 'medium' if score >= 40 else 'low',
                reasons=reasons, components=components,
                analyzed_at=datetime.now(timezone.utc).isoformat())

def url_rep(url):
    return assess_url(url)['score']

def scan_url(value, api_key=None, max_wait=45):
    result = assess_url(value)
    key = api_key or os.environ.get('VT_API_KEY')
    result.update(stats=None, notice=None, analysis_mode='virustotal', virustotal_status='unavailable')
    if not key:
        result['virustotal_status'] = 'not_configured'
        result['notice'] = 'VirusTotal is not configured. Showing custom rules only.'
        return result
    def request(method, endpoint, **kwargs):
        try:
            response = requests.request(method, 'https://www.virustotal.com/api/v3/' + endpoint,
                                        headers={'x-apikey': key}, timeout=15, **kwargs)
            response.raise_for_status()
            return response.json()['data']
        except requests.HTTPError as exc:
            message = {401: 'VirusTotal API key is invalid.', 403: 'VirusTotal access denied.',
                       429: 'VirusTotal rate limit reached. Try again later.'}.get(exc.response.status_code, 'VirusTotal returned an error.')
            raise ScanError(message) from exc
        except (requests.RequestException, ValueError, KeyError) as exc:
            raise ScanError('Could not read a response from VirusTotal. Try again later.') from exc
    try:
        analysis = request('POST', 'urls', data={'url': result['url']})
        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            attributes = request('GET', 'analyses/' + analysis['id'])['attributes']
            if attributes.get('status') == 'completed':
                result['stats'] = attributes['stats']
                result['virustotal_status'] = 'completed'
                return result
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        result['virustotal_status'] = 'pending'
        raise ScanError('VirusTotal analysis is still pending. Try again shortly.')
    except (ScanError, KeyError) as exc:
        result['notice'] = str(exc) if isinstance(exc, ScanError) else 'Incomplete response from VirusTotal.'
    return result

def main():
    try:
        result = scan_url(input('Enter URL: '))
        print(f"Custom risk: {result['score']}/100 ({result['level']})")
        for reason in result['reasons']:
            print(f"+{reason['points']} {reason['label']}")
        print(result['notice'] or result['stats'])
    except (ScanError, EOFError) as exc:
        print(exc)

if __name__ == '__main__':
    main()
