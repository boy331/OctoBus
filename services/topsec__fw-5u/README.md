# TopSec FW 5U

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id topsec-fw-5u ./services/topsec__fw-5u
```

## Instance Configuration

`config.schema.json` contains non-sensitive connection options:

- `host`: TopSec FW 5U WebUI base URL, preferably `https://host:port`.
- `timeoutMs`: HTTP timeout in milliseconds.
- `skipTlsVerify` / `tlsInsecureSkipVerify`: compatibility TLS verification controls for private deployments.
- `allow_http` / `allowHttp`: allow plain HTTP for local mocks or lab environments.
- `headers`: optional additional HTTP headers.

`secret.schema.json` contains credentials:

- `username`: WebUI login username.
- `password`: WebUI login password.

## Behavior

- `Login` maps to `POST /home/login/` and encrypts the password internally with the device AES-128-CBC scheme.
- `Refresh`, `AddToBlacklist`, `RemoveFromBlacklist`, and `Logout` use an internal session cache isolated by service, instance, host, and username.
- `AddToBlacklist` and `RemoveFromBlacklist` take only the target IP plus optional host/TLS flags. Request `session`, `token`, `cookie`, `username`, and `password` fields are deprecated and ignored by SDK handlers.
- Duplicate add results such as `黑名单条目已存在` and missing remove results such as `黑名单索引不存在` are treated as idempotent success.
- Responses and errors do not return upstream raw bodies, raw JSON, cookies, tokens, session state, or parsed login payloads.

## Local Checks

```bash
cd services
npm run validate -- --service-dir topsec__fw-5u
npm test -- --service-dir topsec__fw-5u
```
