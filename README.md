# Ruddarr APNs Worker

The APNs worker stores device tokens in R2.

## Environment Variables

- `APPLE_KEYID`
- `APPLE_TEAMID`
- `AUTHKEY` (encrypted)
- `WEBHOOK_SECRET` (encrypted)

## Testing

```bash
cat payloads/health-restored.json | http post https://notify.ruddarr.com/{icloud-user-id} User-Agent:Radarr/1.0
```

## WAF

The WAF blocks:
- `method` other than `POST`
- `content-type` other than `application/json`
- `path` other than `/register` and `/push/+`
- `user-agent` other than: `Ruddarr/*`, `Radarr/*` and `Sonarr/*`
