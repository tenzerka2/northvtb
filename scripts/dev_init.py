#!/usr/bin/env python3
"""Generate local sandbox credentials once. No secrets are printed."""
import os,pathlib,secrets
root=pathlib.Path('.secrets');env=pathlib.Path('.env')
if env.exists():
    if not (root/'signing.seed').exists():raise SystemExit('Existing .env but signing seed is missing; restore it before starting.')
    print('Existing sandbox configuration preserved.')
else:
    root.mkdir(mode=0o700,exist_ok=True);root.chmod(0o700)
    seed=root/'signing.seed';fd=os.open(seed,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(secrets.token_bytes(32))
    values={'NORTH_DB_PASSWORD':secrets.token_hex(32),'NORTH_APP_DB_PASSWORD':secrets.token_hex(32),'NORTH_PROVIDER_DB_PASSWORD':secrets.token_hex(32),'NORTH_OWNER_TOKEN':secrets.token_hex(32),'NORTH_OWNER_SUBJECT':'sandbox-owner','NORTH_CALLBACK_KEY':secrets.token_hex(32),'NORTH_RUNTIME_UID':str(os.getuid()),'NORTH_RUNTIME_GID':str(os.getgid())}
    fd=os.open(env,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(''.join(k+'='+v+'\n' for k,v in values.items()))
    print('Sandbox configuration created; credentials remain in local files.')
