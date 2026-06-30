# Tencent QYWeiXin Group Robot Service Package

This package preserves legacy gRPC package and method names where applicable.

It keeps the legacy gRPC package and method name for compatibility:

- `Tencent_QYWeiXin_GroupRobot.Tencent_QYWeiXin_GroupRobot/SendText`

The package command is `tencent-qyweixin-group-robot`, and the service root is `services/tencent__qyweixin-group-robot`.

## Behavior

- Requires a full HTTPS WeCom webhook URL in instance secret field `webhook`.
- Sends request `message` as WeCom `text.content`.
- Supports comma-separated `mentioned_mobiles` and camelCase `mentionedMobiles`.
- Returns the upstream HTTP status, parsed `errcode`, and parsed `errmsg`. The legacy `http_body` response field is deprecated and intentionally empty.
- Maps non-2xx, invalid JSON, missing `errcode`, transport failures, and non-zero WeCom business codes to structured gRPC errors.

## Configuration

Config fields:

- `timeoutMs`: upstream HTTP timeout in milliseconds.
- `headers`: optional extra HTTP headers.
- `skipTlsVerify`, `tlsInsecureSkipVerify`, `insecureSkipVerify`: TLS verification aliases.

Secret fields:

- `webhook`: WeCom group robot webhook URL. Deprecated aliases `webhook_url`, `webhookUrl`, and `url` are also accepted as secret fields.

```json
{
  "webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=replace-me"
}
```

## Import

```bash
octobus service import --id tencent-qyweixin-group-robot ./services//tencent__qyweixin-group-robot
```

## Validation

```bash
cd services
npm run validate -- --service-dir tencent__qyweixin-group-robot
npm test -- --service-dir tencent__qyweixin-group-robot --coverage
npm run pack:check
```
