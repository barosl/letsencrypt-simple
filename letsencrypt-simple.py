#!/usr/bin/env python3

import subprocess
import re
import codecs
import json
import base64
import requests
import hashlib
import toml
import textwrap
import os
import shlex
import time

DEFAULT_API_URL = 'https://acme-v01.api.letsencrypt.org/acme/'
STAGING_API_URL = 'https://acme-staging.api.letsencrypt.org/acme/'
AGREEMENT_URL = 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
ACCOUNT_KEY_FILE = 'keys/account.key'
INTERMEDIATE_CERT_URL = 'https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem'
INTERMEDIATE_CERT_FILE = 'keys/lets-encrypt-x1-cross-signed.pem'

class ApiError(Exception):
    def __init__(self, info):
        self.info = info

    def __str__(self):
        return str(self.info)

def b64(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def load_pub_key(fname):
    data = subprocess.check_output(['openssl', 'rsa', '-in', fname, '-text', '-noout']).decode('utf-8')
    mat = re.search(r'modulus:(.+?)publicExponent: (\S+)', data, flags=re.DOTALL)

    mod = re.sub(r'\s|:', '', mat.group(1))
    mod = codecs.decode(mod, 'hex')
    assert mod[0] == 0
    mod = mod[1:]

    exp = '{:x}'.format(int(mat.group(2)))
    if len(exp) % 2: exp = '0' + exp
    exp = codecs.decode(exp, 'hex')

    return b64(mod), b64(exp)

def load_csr(fname):
    return b64(subprocess.check_output(['openssl', 'req', '-in', fname, '-outform', 'DER']))

def write_cert(fname, cert_bin):
    with open(fname, 'w') as fp:
        cert_text = '\n'.join(textwrap.wrap(base64.b64encode(cert_bin).decode('ascii'), 64))
        fp.write('-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n'.format(cert_text))

def retrieve_intermediate():
    if os.path.exists(INTERMEDIATE_CERT_FILE): return

    with open(INTERMEDIATE_CERT_FILE, 'w') as fp:
        fp.write(requests.get(INTERMEDIATE_CERT_URL).text)

class Client:
    def __init__(self, account_key, *, api_url=DEFAULT_API_URL):
        mod, exp = load_pub_key(account_key)

        self.mod = mod
        self.exp = exp

        self.api_url = api_url
        self.nonce = None
        self.account_key = account_key

    def api(self, path, binary=False, **body):
        if not self.nonce:
            self.nonce = requests.head(self.api_url + 'new-reg').headers['Replay-Nonce']

        header = {
            'alg': 'RS256',
            'jwk': {
                'kty': 'RSA',
                'n': self.mod,
                'e': self.exp,
            },
            'nonce': self.nonce,
        }

        if path.startswith(self.api_url):
            path = path[len(self.api_url):]

        pos = path.find('/')
        if pos == -1: body['resource'] = path
        else: body['resource'] = path[:pos]

        protected = b64(json.dumps(header).encode('utf-8'))
        payload = b64(json.dumps(body).encode('utf-8'))
        signature = b64(subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', self.account_key], input='{}.{}'.format(protected, payload).encode('utf-8')))

        req = {
            'header': {},
            'protected': protected,
            'payload': payload,
            'signature': signature,
        }

        res = requests.post(self.api_url + path, json=req)

        self.nonce = res.headers['Replay-Nonce']

        if res.status_code >= 300:
            raise ApiError(res.json())

        if binary: return res.content
        else: return res.json()

    def challenge(self, info, domain):
        js = json.dumps({'kty': 'RSA', 'n': self.mod, 'e': self.exp}, sort_keys=True, separators=(',', ':'))
        thumbprint = b64(hashlib.sha256(js.encode('utf-8')).digest())
        key_auth = '{}.{}'.format(info['token'], thumbprint)

        local_fname = info['token']
        local_path = '/.well-known/acme-challenge/{}'.format(local_fname)
        local_content = key_auth

        print('----')
        print('1. Create a file at')
        print('   http://{}{}'.format(domain, local_path))
        print('2. Fill the content as')
        print('   {}'.format(local_content))
        print('3. Note that you must *not* append a new line at the end of the file. If you\'re in doubt, you can use the following command:')
        print('   echo -n {} > {}'.format(shlex.quote(local_content), shlex.quote(local_fname)))
        input('4. Press enter when you\'re done: ')
        print('----')

        return self.api(info['uri'], keyAuthorization=key_auth)

def main():
    try: os.mkdir('keys')
    except FileExistsError: pass

    with open('cfg.toml') as fp:
        cfg = toml.loads(fp.read())

    if not os.path.exists(ACCOUNT_KEY_FILE):
        subprocess.check_call(['openssl', 'genrsa', '-out', ACCOUNT_KEY_FILE, '2048'])

    api_url = STAGING_API_URL if cfg.get('server', {}).get('staging', False) else DEFAULT_API_URL
    cli = Client(ACCOUNT_KEY_FILE, api_url=api_url)

    try: cli.api('new-reg', agreement=AGREEMENT_URL)
    except ApiError as e:
        if 'already in use' in e.info['detail']: pass
        else: raise

    for domain in cfg['cert']['domains']:
        res = cli.api('new-authz', identifier={'type': 'dns', 'value': domain})
        info = [x for x in res['challenges'] if x['type'] == 'http-01'][0]

        cli.challenge(info, domain)

        for i in range(10):
            if requests.get(info['uri']).json()['status'] != 'pending': break
            time.sleep(0.5)

        fname = 'keys/{}.csr'.format(domain)
        if os.path.exists(fname):
            csr = load_csr(fname)
        else:
            fname = 'keys/{}.key'.format(domain)
            if not os.path.exists(fname):
                subprocess.check_call(['openssl', 'genrsa', '-out', fname, '2048'])

            csr = b64(subprocess.check_output(['openssl', 'req', '-new', '-key', fname, '-subj', '/CN={}'.format(domain), '-outform', 'DER']))

        cert_bin = cli.api('new-cert', csr=csr, binary=True)

        fname = 'keys/{}.crt'.format(domain)
        write_cert(fname, cert_bin)

        if cfg['cert'].get('chain', True):
            retrieve_intermediate()

            with open(fname, 'a') as fp:
                with open(INTERMEDIATE_CERT_FILE) as fp_from:
                    fp.write(fp_from.read())

        print('----')
        print('* Issued {}'.format(fname))
        print('----')

if __name__ == '__main__':
    main()
