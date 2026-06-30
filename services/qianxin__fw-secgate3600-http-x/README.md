# QIANXIN FW SecGate3600 HTTP_X

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id qianxin-fw-secgate3600-http-x ./services//qianxin__fw-secgate3600-http-x
```

## Behavior

- Configure `host` in instance config and `user`/`password` in instance secret. Legacy `LoginRequest.user` and `LoginRequest.password` are deprecated and ignored.
- `Login` maps to `GET /webui/login/auth` with the WebUI login query parameters built from instance secret.
- `BlockIP` maps to `POST /webui/blacklist/set?uuid=...` with JSON body `{ ip, mask, desc? }`, using the uuid cached by a prior `Login` for the same instance, host, and user.
- `UnblockIP` uses the cached login uuid as well. Deprecated request `uuid` fields are ignored.
- `UnblockIP` uses the same endpoint and adds `undo=1` to the JSON body.
- Login responses do not return cookies, raw login body, raw JSON, `Set-Cookie`, `Authorization`, or an effective URL containing credentials. Retained raw/header/effective URL proto fields are deprecated.
- Non-login HTTP responses are returned as normalized `DeviceHttpResponse` objects with status, sanitized response headers, raw body, parsed JSON when available, and effective URL.

## Config And Secret

Config:

```json
{
  "host": "https://198.51.100.10:8443",
  "timeoutMs": 5000,
  "skipTlsVerify": false
}
```

Secret:

```json
{
  "user": "admin",
  "password": "REDACTED"
}
```

## Local Checks

```bash
cd services
npm run validate -- --service-dir qianxin__fw-secgate3600-http-x
npm test -- --service-dir qianxin__fw-secgate3600-http-x --coverage
npm run pack:check
```
