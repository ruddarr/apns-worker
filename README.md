# Ruddarr APNs Worker

The APNs worker that poweres Ruddarr's push notifications.

## Environment Variables

- `APPLE_KEYID`
- `APPLE_TEAMID`
- `APPLE_AUTHKEY` (encrypted)
- `WEBHOOK_SECRET` (encrypted)

## Testing

```bash
cat payloads/health-restored.json | http post https://notify.ruddarr.com/{CK.UserRecordID} User-Agent:Radarr/1.0
```

## WAF

The WAF blocks:
- `method` other than `POST`
- `content-type` other than `application/json`
- `path` other than `/register` and `/push/+`
- `user-agent` other than: `Ruddarr/*`, `Radarr/*` and `Sonarr/*`
