# Ruddarr APNs Worker

The APNs worker stores device tokens in R2.

## Environment Variables

- `APPLE_KEYID`
- `APPLE_TEAMID`
- `AUTHKEY` (encrypted)
- `WEBHOOK_SECRET` (encrypted)

## WAF

The WAF blocks:
- `method` other than `POST`
- `content-type` other than `application/json`
- `path` other than `/register` and `/push/+`
- `user-agent` other than: `Ruddarr/*`, `Radarr/*` and `Sonarr/*`
