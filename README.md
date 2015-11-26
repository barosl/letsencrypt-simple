# letsencrypt-simple

letsencrypt-simple is a simple single-file ACME client that is compatible with [Let's Encrypt][le].

## Instructions

1. Create a virtual environment.
2. `pip install -r requirements.txt`
3. Copy `cfg.sample.toml` to `cfg.toml`.
4. Add appropriate domains.
5. Run `./letsencrypt-simple.py`

## Notes

- The private key files are kept in the `keys` directory. These include the account key (`account.key`) and the domain keys for each domain (`DOMAIN.key`).
- The issued certificates are also kept in the same directory (`DOMAIN.crt`).
- The `openssl` command is required to work properly.

[le]: https://letsencrypt.org/
