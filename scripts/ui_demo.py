#!/usr/bin/env python3
"""Exercise the browser BFF against real PostgreSQL and the sandbox worker."""
import http.cookiejar
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

base = os.environ.get('NORTH_DEMO_URL', 'http://127.0.0.1:18080')
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
run = secrets.token_hex(8)


def call(method, path, body=None, agent=None, key=None, want=200, origin=None):
    headers = {'Content-Type': 'application/json', 'X-North-UI': '1', 'Origin': origin or base}
    if method == 'POST':
        headers['Idempotency-Key'] = key or secrets.token_hex(16)
    if agent:
        headers['X-North-Agent'] = agent
    req = urllib.request.Request(base + path, method=method, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        response = client.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    data = json.load(response)
    assert response.status == want, (path, response.status, data)
    time.sleep(.06)
    return data


with tempfile.TemporaryFile() as log:
    process = subprocess.Popen([os.environ['NORTH_DEMO_BINARY']], stdout=log, stderr=log)
    try:
        for _ in range(100):
            try:
                call('GET', '/readyz')
                break
            except (urllib.error.URLError, AssertionError):
                time.sleep(.1)
        else:
            raise RuntimeError('UI server did not become ready')
        assert b'NORTH' in client.open(base + '/').read()
        call('GET', '/ui/workspace', want=401)
        call('POST', '/ui/session', {'token': os.environ['NORTH_OWNER_TOKEN']},
             origin='https://attacker.example', want=403)
        call('POST', '/ui/session', {'token': os.environ['NORTH_OWNER_TOKEN']})
        cookie = next(iter(jar))
        assert cookie.has_nonstandard_attr('HttpOnly')
        registration = call('POST', '/ui/api/v1/agents', {}, key=run+'-register')
        assert 'agent_token' not in registration
        assert call('POST', '/ui/api/v1/agents', {}, key=run+'-register') == registration
        aid = registration['agent_id']
        terms = dict(agent_id=aid, action='purchase', purpose='Купить монитор',
                     product='Dell UltraSharp U2723QE', category='electronics', condition='new',
                     max_amount=8500000, currency='RUB', merchants=['dns', 'citilink'],
                     require_verified=True, allow_merchant_approval=True, max_risk=0,
                     max_uses=1, expires_at=int(time.time())+3600)

        def mandate():
            draft = call('POST', '/ui/api/v1/mandates', {'terms': terms})
            call('POST', '/ui/api/v1/mandates/approve', dict(agent_id=aid,
                 mandate_id=draft['mandate_id'], digest=draft['digest']))
            return draft['mandate_id']

        mid = mandate()
        offers = call('GET', '/ui/offers?mandate='+mid)
        assert {o['offer']['merchant_id']: o['policy']['decision'] for o in offers} == {
            'dns': 'ALLOW', 'citilink': 'DENY', 'technopark': 'ASK_USER'}
        workspace = call('GET', '/ui/workspace')
        assert all(m['terms']['owner'] == os.environ['NORTH_OWNER_SUBJECT'] for m in workspace['mandates'])
        assert all(m['reserved_uses'] == 0 for m in workspace['mandates']), 'preview reserved authority'
        assert workspace['digests'][mid]
        item = next(o for o in offers if o['offer']['merchant_id'] == 'technopark')
        auth = call('POST', '/ui/agent/authorizations', {'transaction': item['transaction']}, aid)
        assert auth['policy']['decision'] == 'ASK_USER'
        approval = dict(agent_id=aid, mandate_id=mid, challenge_id=auth['challenge_id'],
                        transaction_hash=item['transaction_hash'])
        call('POST', '/ui/api/v1/challenges/approve', dict(approval, transaction_hash='0'*64), want=403)
        call('POST', '/ui/api/v1/challenges/approve', approval)
        auth = call('POST', '/ui/agent/authorizations', {'transaction': item['transaction']}, aid)
        assert auth['policy']['decision'] == 'ALLOW'
        execution = dict(grant=auth['grant'], transaction=item['transaction'])
        result = call('POST', '/ui/agent/payments', execution, aid, run+'-payment')
        assert call('POST', '/ui/agent/payments', execution, aid, run+'-payment') == result
        for _ in range(60):
            workspace = call('GET', '/ui/workspace')
            payment = next(p for p in workspace['payments'] if p['id'] == result['payment_id'])
            if payment['state'] == 'SUCCEEDED':
                break
            time.sleep(.2)
        else:
            raise RuntimeError('UI payment did not settle')
        assert next(m for m in workspace['mandates'] if m['terms']['id'] == mid)['state'] == 'CONSUMED'
        call('POST', '/ui/agent/payments', execution, aid, want=403)
        mid2 = mandate()
        call('POST', '/ui/api/v1/mandates/revoke', dict(agent_id=aid, mandate_id=mid2))
        assert all(o['policy']['decision'] == 'DENY' for o in call('GET', '/ui/offers?mandate='+mid2))
        call('POST', '/ui/api/v1/agents/revoke', dict(agent_id=aid))
        call('POST', '/ui/agent/authorizations', {'transaction': item['transaction']}, aid, want=403)
        call('DELETE', '/ui/session')
        call('GET', '/ui/workspace', want=401)
        print('UI BFF E2E PASSED: consent, exact hash, payment, replay, revocation, session boundary')
        if os.environ.get('NORTH_BROWSER_TEST') == '1':
            subprocess.run(['node', 'scripts/ui_browser.cjs'], check=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
