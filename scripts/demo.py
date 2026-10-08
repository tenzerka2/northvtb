#!/usr/bin/env python3
"""Reproducible owner/agent HTTP demo. Never prints credentials."""
import json, os, subprocess, time, urllib.request, urllib.error, pathlib, sys, tempfile
for line in pathlib.Path('.env').read_text().splitlines() if pathlib.Path('.env').exists() else []:
    if line.startswith('NORTH_') and '=' in line:
        k,v=line.split('=',1);os.environ.setdefault(k,v)
base=os.environ.get('NORTH_DEMO_URL','http://127.0.0.1:8080')
owner=os.environ['NORTH_OWNER_TOKEN']
process=None
logfile=None
if '--spawn' in sys.argv:
    logfile=tempfile.TemporaryFile(mode='w+b')
    process=subprocess.Popen([os.environ['NORTH_DEMO_BINARY']],stdout=logfile,stderr=logfile)
def call(method,path,token=None,body=None,key=None,want=200):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if key:headers['Idempotency-Key']=key
    request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers=headers)
    try: response=urllib.request.urlopen(request,timeout=20)
    except urllib.error.HTTPError as error: response=error
    data=json.load(response)
    assert response.status==want,(path,response.status,data)
    return data
try:
    for _ in range(100):
        try:call('GET','/readyz');break
        except (urllib.error.URLError,AssertionError):time.sleep(.1)
    else:raise RuntimeError('readiness did not become healthy')
    run=os.urandom(8).hex()
    registration=call('POST','/v1/agents',owner,{},run+'-agent')
    aid=registration['agent_id'];agent=registration['agent_token']
    assert call('POST','/v1/agents',owner,{},run+'-agent')==registration
    terms=dict(agent_id=aid,action='purchase',purpose='console',product='PS5-Pro',category='gaming',condition='new',max_amount=8500000,currency='RUB',merchants=[],require_verified=True,allow_risk_approval=False,max_risk=20,max_uses=1,expires_at=int(time.time())+3600)
    def mandate(suffix):
        draft=call('POST','/v1/mandates',owner,{'terms':terms},run+'-draft-'+suffix)
        approval={'agent_id':aid,'mandate_id':draft['mandate_id'],'digest':draft['digest']}
        call('POST','/v1/mandates/approve',agent,approval,run+'-attack-'+suffix,want=403)
        result=call('POST','/v1/mandates/approve',owner,approval,run+'-approve-'+suffix)
        return result
    m=mandate('one')
    offers=call('GET','/v1/offers?product=PS5-Pro',agent)
    offers=[o for o in offers if o['id'].startswith('demo-')]
    assert len(offers)==3,'seed scripts/seed.sql before running demo'
    def transaction(offer,mid):
        t={k:offer[k] for k in ['product','category','condition','currency','quantity','unit_amount','fees','shipping','amount']}
        t.update(schema_version=1,mandate_id=mid,agent_id=aid,merchant_id=offer['merchant_id'],offer_id=offer['id'],offer_revision=offer['revision'],action='purchase',purpose='console')
        return t
    for o,expected in zip(offers,['DENY','DENY','ALLOW']):
        tx=transaction(o,m['terms']['id'])
        decision=call('POST','/v1/authorizations',agent,{'transaction':tx},run+'-'+o['id'])
        assert decision['policy']['decision']==expected,decision
        print(f"{o['amount']//100:,} RUB -> {expected}")
        if expected=='ALLOW':grant=decision['grant'];valid_offer=o
    execution={'grant':grant,'transaction':tx}
    result=call('POST','/v1/payments',agent,execution,run+'-execute')
    assert call('POST','/v1/payments',agent,execution,run+'-execute')==result
    pid=result['payment_id']
    for _ in range(100):
        status=call('GET','/v1/payments/'+pid,owner)
        if status['state']=='SUCCEEDED':break
        time.sleep(.1)
    else:raise RuntimeError('payment did not settle')
    consumed=call('GET','/v1/mandates/'+m['terms']['id'],owner)
    assert consumed['state']=='CONSUMED' and consumed['consumed_uses']==1 and consumed['reserved_uses']==0,consumed
    call('POST','/v1/payments',agent,execution,run+'-replay',want=403)
    print('Payment SUCCEEDED; mandate CONSUMED 1/1; replay blocked')
    other=call('POST','/v1/agents',owner,{},run+'-other-agent')
    call('POST','/v1/authorizations',other['agent_token'],{'transaction':dict(tx,agent_id=other['agent_id'])},run+'-stolen-mandate',want=403)
    call('POST','/v1/payments',other['agent_token'],execution,run+'-stolen-grant',want=403)
    second=mandate('tamper');newtx=transaction(valid_offer,second['terms']['id'])
    authorized=call('POST','/v1/authorizations',agent,{'transaction':newtx},run+'-tamper-grant')
    changed=dict(newtx,amount=9299000,unit_amount=9299000)
    denied=call('POST','/v1/payments',agent,{'grant':authorized['grant'],'transaction':changed},run+'-tamper-execute',want=422)
    assert denied['error']['code']=='TRANSACTION_HASH_MISMATCH',denied
    print('82,990 -> 92,990 RUB tampering blocked: TRANSACTION_HASH_MISMATCH')
    call('POST','/v1/mandates/revoke',owner,{'agent_id':aid,'mandate_id':second['terms']['id']},run+'-cleanup')
    refund=call('POST','/v1/refunds',owner,{'payment_id':pid},run+'-refund')
    for _ in range(100):
        status=call('GET','/v1/refunds/'+refund['refund_id'],owner)
        if status['state']=='SUCCEEDED':break
        time.sleep(.1)
    else:raise RuntimeError('refund did not settle')
    consumed=call('GET','/v1/mandates/'+m['terms']['id'],owner)
    assert consumed['consumed_uses']==1
    print('Refund SUCCEEDED; purchasing authority remains consumed')
    print('HTTP END-TO-END DEMO PASSED')
except Exception:
    if logfile:
        logfile.seek(0);print(logfile.read().decode(errors='replace'),file=sys.stderr)
    raise
finally:
    if process:
        process.terminate();process.wait(timeout=20)
    if logfile:logfile.close()
