#!/usr/bin/env python3
import os,pathlib,secrets,subprocess,tempfile
with tempfile.TemporaryDirectory(prefix='north-demo-') as tmp:
    seed=pathlib.Path(tmp)/'signing.seed';seed.write_bytes(secrets.token_bytes(32));seed.chmod(0o600)
    env=os.environ.copy();env.update(NORTH_MODE='sandbox',NORTH_OWNER_TOKEN=secrets.token_hex(32),NORTH_OWNER_SUBJECT='sandbox-owner',NORTH_CALLBACK_KEY=secrets.token_hex(32),NORTH_SIGNING_SEED_FILE=str(seed),NORTH_DATABASE_URL=env['NORTH_TEST_DSN'],NORTH_PROVIDER_DATABASE_URL=env['NORTH_TEST_PROVIDER_DSN'],NORTH_LISTEN_ADDR='127.0.0.1:18080',NORTH_DEMO_URL='http://127.0.0.1:18080',NORTH_DEMO_BINARY='/tmp/north-demo')
    subprocess.run(['python3','scripts/demo.py','--spawn'],env=env,check=True)
    env['NORTH_OWNER_SUBJECT']='ui-owner'
    subprocess.run(['python3','scripts/ui_demo.py'],env=env,check=True)
