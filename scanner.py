"""Shared URL scoring and VirusTotal scanner for CLI and web."""
import os
import time
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
    reasons = []
    if parts.scheme != 'https':
        reasons.append(('Connection uses HTTP instead of HTTPS', 20))
    for word in ('login', 'verify', 'update', 'secure', 'account', 'bank'):
        if word in url.lower():
            reasons.append((f"URL contains '{word}'", 10))
    if any(host == s or host.endswith('.' + s) for s in ('bit.ly', 'tinyurl.com', 'tinyurl', 't.co', 'is.gd')):
        reasons.append(('Known URL shortening service', 15))
    if len(url) > 75:
        reasons.append(('URL is longer than 75 characters', 10))
    if any(c.isdigit() for c in host):
        reasons.append(('Hostname contains numbers', 25))
    score = min(sum(points for _, points in reasons), 100)
    return dict(url=url, score=score, level='high' if score >= 70 else 'medium' if score >= 40 else 'low',
                reasons=[dict(label=label, points=points) for label, points in reasons])

def url_rep(url):
    return assess_url(url)['score']

def scan_url(value, api_key=None, max_wait=45):
    result = assess_url(value)
    key = api_key or os.environ.get('VT_API_KEY')
    result.update(stats=None, notice=None)
    if not key:
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
                return result
            time.sleep(min(5, max(0, deadline - time.monotonic())))
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
