# TopSec FW 2U

This package preserves legacy gRPC package and method names where applicable.

## Import

```bash
octobus service import --id topsec-fw-2u ./services/topsec__fw-2u
```

## Instance Configuration

`config.schema.json` contains non-sensitive connection options:

- `host`: TopSec FW 2U WebUI base URL with `http` or `https` scheme.
- `timeoutMs`: HTTP timeout in milliseconds.
- `skipTlsVerify` / `tlsInsecureSkipVerify` / `insecureSkipVerify`: compatibility TLS verification controls for private deployments.

`secret.schema.json` contains credentials:

- `username`: WebUI login username.
- `password`: WebUI login password.

## Behavior

- `Login` performs an internal login and only returns `status_code`, `success`, and `message`.
- `ActivatePermission`, `AddBlacklistIP`, `DeleteBlacklistIP`, and `Logout` use an internal session cache isolated by service, instance, host, and username.
- `AddBlacklistIP` and `DeleteBlacklistIP` take only the target IP list plus optional host override. Request `session`, `token`, `cookie`, `secret`, `username`, and `password` fields are deprecated and ignored by SDK handlers.
- Responses do not return upstream raw bodies, cookies, tokens, session secrets, or parsed login payloads.

## Local Checks

```bash
cd services
npm run validate -- --service-dir topsec__fw-2u
npm test -- --service-dir topsec__fw-2u
```
