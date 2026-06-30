# TopSec FW V3.7.6

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id topsec-fw-v3-7-6 ./services/topsec__fw_v3-7-6
```

## Instance Configuration

`config.schema.json` contains non-sensitive connection options:

- `host`: TopSec FW V3.7.6 WebUI base URL.
- `memo`: default memo for added blacklist entries.
- `timeoutMs`: HTTP timeout in milliseconds.
- `skipTlsVerify` / `tlsInsecureSkipVerify`: compatibility TLS verification controls for private deployments.
- `allow_http` / `allowHttp`: allow plain HTTP for local mocks or lab environments.
- `headers`: optional additional HTTP headers.

`secret.schema.json` contains credentials and encryption material:

- `username`: WebUI login username.
- `password`: WebUI login password.
- `aesKey`: AES key as hex, base64, or UTF-8 text.
- `aesIv`: AES IV as hex, base64, or UTF-8 text.

Legacy request fields `username`, `password`, `aes_key`, and `aes_iv`, plus config fields `user`, `username`, `aesKey`, and `aesIv`, are retained only as deprecated compatibility surface. SDK handlers prefer `ctx.secret` and do not read credential or AES material from `ctx.request`.

## Behavior

- `Login` maps to `POST /home/restLogin/`; it encrypts `password` and `ngtosAuth` internally with AES-CBC zero padding.
- `AddBlacklistIP`, `DeleteBlacklistIP`, and `Logout` use an internal session cache isolated by service, instance, host, and username.
- `AddBlacklistIP` and `DeleteBlacklistIP` take the target IP list and optional memo. Request session, token, cookie, and secret fields are deprecated and ignored by SDK handlers.
- Duplicate entries and already-absent entries are treated as idempotent success where the upstream response clearly indicates that state.
- Responses and errors do not return upstream raw payloads, raw JSON, cookies, tokens, session secrets, or parsed login payloads.

## Local Checks

```bash
cd services
npm run validate -- --service-dir topsec__fw_v3-7-6
npm test -- --service-dir topsec__fw_v3-7-6
```
