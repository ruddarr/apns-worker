export default {
  async fetch(request, env, context) {
    const { headers } = request

    console.info(`URL: ${request.url}`)
    console.info(`User-Agent: ${headers.get('user-agent')}`)
    console.info(`CF-Connecting-IP: ${headers.get('cf-connecting-ip')}`)

    const url = new URL(request.url)
    const payload = await request.json()

    console.info('Payload: ' + JSON.stringify(payload).replace(/\\/g, ''))

    if (url.pathname == '/register') {
      return registerDevice(env, payload)
    }

    if (url.pathname.startsWith('/push/') && isValidWebhookRequest(url, payload)) {
      const { timestamp, account } = parsePushUrl(url)

      const validSignature = await verifyWebhookSignature(env, headers, `${timestamp}:${account}`)

      if (! validSignature) {
        return statusResponse(403, 'invalid webhook signature')
      }

      if (daysSince(timestamp) > 30) {
        return statusResponse(410, 'webhook URL expired')
      }

      if (payload.eventType == 'Test') {
        return statusResponse(202)
      }

      if (['MovieFileDelete', 'EpisodeFileDelete', 'Grab', 'Download'].includes(payload.eventType)) {
        await sendDebugEmail(payload.eventType, payload, env)
      }

      console.info(`Type: ${payload.eventType}`)

      return handleWebhook(env, account, payload)
    }

    return statusResponse(400)
  },
}

function statusResponse(code, message = null) {
  console.info(`Response: ${code}`)

  return Response.json(
    { status: code, message },
    { status: code }
  )
}

function isValidWebhookRequest(url, payload) {
  if (! Object.hasOwn(payload, 'eventType') || ! payload.eventType) {
    return false
  }

  const { timestamp, account } = parsePushUrl(url)

  if (isNaN(timestamp) || timestamp < 1700000000) {
    return false
  }

  if (account.length < 32 || ! /^[0-9a-f_]+$/.test(account)) {
    return false
  }

  return true
}

function parsePushUrl(url) {
  const data = url.pathname
    .replace('/push/', '')
    .replace('/', '')

  const [timestamp, account] = atob(data).split(':')

  return { timestamp: parseInt(timestamp), account }
}

function daysSince(timestamp) {
  const now = new Date().getTime() / 1000

  return Math.round(
    (now - timestamp) / (60 * 60 * 24)
  )
}

async function registerDevice(env, payload) {
  const message = `${payload.account}:${payload.token}`
  const validSignature = await verifySignature(env, payload.signature, message)

  if (! validSignature) {
    return statusResponse(403, 'invalid webhook signature')
  }

  let data = await env.STORE.get(payload.account, { type: 'json' })

  if (data === null) {
    data = { devices: [] }
  }

  const devices = new Set(data.devices)
  const deviceRegistered = devices.has(payload.token)

  devices.add(payload.token)

  data.seenAt = Math.floor(Date.now() / 1000)
  data.entitledAt = payload.entitledAt
  data.devices = Array.from(devices)

  await env.STORE.put(payload.account, JSON.stringify(data))

  return statusResponse(deviceRegistered ? 200 : 201)
}

async function deregisterDevice(account, token, env) {
  let data = await env.STORE.get(account, { type: 'json' })

  if (data === null) {
    return
  }

  const devices = new Set(data.devices)

  if (devices.has(token)) {
    devices.delete(token)
    data.devices = Array.from(devices)

    await env.STORE.put(account, JSON.stringify(data))
  }
}

async function handleWebhook(env, account, payload) {
  const data = await env.STORE.get(account, { type: 'json' })
  const devices = data?.devices ?? []

  if (data == null || ! devices.length) {
    return statusResponse(202)
  }

  const entitledAt = data?.entitledAt ?? 0

  if (daysSince(entitledAt) > 30) {
    return statusResponse(402, 'device entitlement expired')
  }

  const notification = buildNotificationPayload(payload)

  if (! notification) {
    return statusResponse(202)
  }

  console.info('Notification: ' + JSON.stringify(notification).replace(/\\/g, ''))
  console.info('Devices: ' + JSON.stringify(devices).replace(/\\/g, ''))

  const authorization = await generateAuthorizationToken(env)

  // send notifications in parallel
  await Promise.all(devices.map(async (device) => {
    await sendNotification(notification, device, account, authorization, env)
  }))

  return statusResponse(202)
}

async function sendNotification(notification, device, account, authorization, env, sandbox = false) {
  const host = sandbox
    ? 'https://api.sandbox.push.apple.com'
    : 'https://api.push.apple.com'

  const url = `${host}/3/device/${device}`

  const days = sandbox ? 2 : 14
  const dayInSeconds = 86400
  const now = Math.floor(Date.now() / 1000)

  const init = {
    method: 'POST',
    body: JSON.stringify(notification),
    headers: {
      'content-type': 'application/json;charset=UTF-8',
      'authorization': `Bearer ${authorization}`,
      'apns-topic': 'com.ruddarr',
      'apns-push-type': 'alert',
      'apns-expiration': `${now + (dayInSeconds * days)}`,
    },
  }

  const response = await fetch(url, init)
  const { headers } = response

  const apnsId = (headers.get('apns-unique-id') || '').toLowerCase()

  if (response.status < 400) {
    console.info(`APNs returned status ${response.status} (sandbox: ${+sandbox}, apnsId: ${apnsId}, device: ${device})`)

    return { success: true, apnsId, device }
  }

  const json = await response.json()
  const message = json?.reason ?? 'Unknown'

  console.error(`APNs returned status ${response.status}: ${message} (sandbox: ${+sandbox}, apnsId: ${apnsId}, device: ${device})`)

  if (response.status == 400 && message == 'BadDeviceToken') {
    if (! sandbox) {
      return sendNotification(notification, device, account, authorization, env, true)
    }

    await deregisterDevice(account, device, env)
  }

  if (response.status == 410 && ['ExpiredToken', 'Unregistered'].includes(message)) {
    await deregisterDevice(account, device, env)
  }

  return { success: false, message, apnsId, device }
}

async function generateAuthorizationToken(env) {
  const storedToken = await env.STORE.get('$token')

  if (storedToken !== null) {
    return storedToken
  }

  const payload =  {
    iss: env.APPLE_TEAMID,
    iat: Math.floor(Date.now() / 1000),
  }

  const header = { kid: env.APPLE_KEYID, typ: 'JWT' }

  const algorithm = {
    name: 'ECDSA',
    namedCurve: 'P-256',
    hash: { name: 'SHA-256' },
  }

  const jwtHeader = textToBase64Url(JSON.stringify({ ...header, alg: 'ES256' }))
  const jwtPayload = textToBase64Url(JSON.stringify(payload))

  const key = await crypto.subtle.importKey(
    'pkcs8', pemToBinary(env.APPLE_AUTHKEY), algorithm, true, ['sign']
  )

  const signature = await crypto.subtle.sign(
    algorithm, key, textToArrayBuffer(`${jwtHeader}.${jwtPayload}`)
  )

  const token = `${jwtHeader}.${jwtPayload}.${arrayBufferToBase64Url(signature)}`

  await env.STORE.put('$token', token, { expirationTtl: 60 * 45 })

  return token
}

function buildNotificationPayload(payload) {
  const instanceName = payload.instanceName?.trim().length > 0 ? payload.instanceName : 'Unknown'
  const encodedInstanceName = encodeURIComponent(instanceName)
  const isSeries = payload.hasOwnProperty('series')

  const title = payload.series?.title ?? payload.movie?.title ?? 'Unknown'
  const year = ((yyyy) => yyyy === 0 ? "Unknown" : yyyy)(payload.series?.year ?? payload.movie?.year ?? 0)
  const threadId = payload.series?.tvdbId ?? payload.movie?.tmdbId
  const posterUrl = (payload.series ?? payload.movie)?.images?.find(image => image.coverType === 'poster')?.remoteUrl;

  const episodes = payload.episodes?.length
  const episode = payload.episodes?.[0]?.episodeNumber
  const season = payload.episodes?.[0]?.seasonNumber
  const message = payload.message?.replace(' (Prowlarr)', '')

  switch (payload.eventType) {
    case 'RuddarrTest':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_TEST',
            'loc-key': 'NOTIFICATION_TEST_BODY',
          },
          'sound': 'ping.aiff',
          'relevance-score': 0.2,
        },
        eventType: payload.eventType,
      }

    case 'ApplicationUpdate':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_APPLICATION_UPDATE',
            'title-loc-args': [instanceName],
            'body': payload.message,
          },
          'sound': 'ping.aiff',
          'relevance-score': 1.0,
        },
        eventType: payload.eventType,
      }

    case 'Health':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_HEALTH',
            'title-loc-args': [instanceName],
            'body': message,
          },
          'sound': 'ping.aiff',
          'thread-id': `health:${payload.type}`,
          'relevance-score': 0.8,
        },
        eventType: `${payload.eventType}:${payload.type}`,
      }

    case 'HealthRestored':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_HEALTH_RESTORED',
            'title-loc-args': [instanceName],
            'body': message,
          },
          'sound': 'ping.aiff',
          'thread-id': `health:${payload.type}`,
          'relevance-score': 1.0,
        },
        eventType: `${payload.eventType}:${payload.type}`,
      }

    case 'MovieAdded':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_MOVIE_ADDED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_MOVIE_ADDED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `movie:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        deeplink: `ruddarr://movies/open/${payload.movie?.id}?instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'MovieDelete':
      // "deletedFiles": true, "movieFolderSize": 24646765223,
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_MOVIE_DELETED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_MOVIE_DELETED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `movie:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        poster: posterUrl,
      }

    case 'MovieFileDelete':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_MOVIE_FILE_DELETED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_MOVIE_FILE_DELETED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `movie:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        deeplink: `ruddarr://movies/open/${payload.movie?.id}?instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'SeriesAdd':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_SERIES_ADDED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_SERIES_ADDED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `series:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        deeplink: `ruddarr://series/open/${payload.series?.id}?instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'SeriesDelete':
      // "deletedFiles": true
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_SERIES_DELETED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_SERIES_DELETED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `series:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        poster: posterUrl,
      }

    case 'EpisodeFileDelete':
      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_EPISODE_FILE_DELETED',
            'title-loc-args': [instanceName],
            'loc-key': 'NOTIFICATION_EPISODE_FILE_DELETED_BODY',
            'loc-args': [title, year],
          },
          'sound': 'ping.aiff',
          'thread-id': `series:${threadId}`,
          'relevance-score': 0.6,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        deeplink: `ruddarr://series/open/${payload.series?.id}?instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'Grab':
      const indexerName = formatIndexer(payload.release.indexer)

      if (! isSeries) {
        return {
          aps: {
            'alert': {
              'title-loc-key': 'NOTIFICATION_MOVIE_GRAB',
              'title-loc-args': [instanceName],
              'subtitle-loc-key': 'NOTIFICATION_MOVIE_GRAB_SUBTITLE',
              'subtitle-loc-args': [title, year],
              'loc-key': 'NOTIFICATION_MOVIE_GRAB_BODY',
              'loc-args': [payload.release.quality, indexerName],
            },
            'sound': 'ping.aiff',
            'thread-id': `movie:${threadId}`,
            'relevance-score': 0.8,
            'mutable-content': 1,
          },
          eventType: payload.eventType,
          hideInForeground: true,
          deeplink: `ruddarr://movies/open/${payload.movie?.id}?instance=${encodedInstanceName}`,
          poster: posterUrl,
        }
      }

      if (episodes === 1) {
        return {
          aps: {
            'alert': {
              'title-loc-key': 'NOTIFICATION_EPISODE_GRAB',
              'title-loc-args': [instanceName],
              'subtitle-loc-key': 'NOTIFICATION_EPISODE_GRAB_SUBTITLE',
              'subtitle-loc-args': [title, season, episode],
              'loc-key': 'NOTIFICATION_EPISODES_GRAB_BODY',
              'loc-args': [payload.release.quality, indexerName],
            },
            'sound': 'ping.aiff',
            'thread-id': `series:${threadId}`,
            'relevance-score': 0.8,
            'mutable-content': 1,
          },
          eventType: payload.eventType,
          hideInForeground: true,
          deeplink: `ruddarr://series/open/${payload.series?.id}?season=${season}&episode=${episode}&instance=${encodedInstanceName}`,
          poster: posterUrl,
        }
      }

      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_EPISODES_GRAB',
            'title-loc-args': [instanceName, episodes],
            'subtitle-loc-key': 'NOTIFICATION_EPISODES_GRAB_SUBTITLE',
            'subtitle-loc-args': [title, season],
            'loc-key': 'NOTIFICATION_EPISODES_GRAB_BODY',
            'loc-args': [payload.release.quality, indexerName],
          },
          'sound': 'ping.aiff',
          'thread-id': `series:${threadId}`,
          'relevance-score': 0.8,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        hideInForeground: true,
        deeplink: `ruddarr://series/open/${payload.series?.id}?season=${season}&instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'Download':
      const subtype = payload.isUpgrade ? 'UPGRADE' : 'DOWNLOAD'

      if (payload.isUpgrade) {
        // const fromQuality = payload.isUpgrade ? payload.deletedFiles[0].quality : null
        // const toQuality = payload.isUpgrade ? payload.episodeFile.quality : null
      }

      if (! isSeries) {
        return {
          aps: {
            'alert': {
              'title-loc-key': `NOTIFICATION_MOVIE_${subtype}`,
              'title-loc-args': [instanceName],
              'loc-key': 'NOTIFICATION_MOVIE_DOWNLOAD_BODY',
              'loc-args': [title, year],
            },
            'sound': 'ping.aiff',
            'thread-id': `movie:${threadId}`,
            'relevance-score': 1.0,
            'mutable-content': 1,
          },
          eventType: payload.eventType,
          deeplink: `ruddarr://movies/open/${payload.movie?.id}?instance=${encodedInstanceName}`,
          poster: posterUrl,
        }
      }

      if (episodes === 1) {
        const releaseTitle = payload.release?.releaseTitle?.replace('.', ' ').toUpperCase()
        const seasonPadded = String(season).padStart(2, '0')
        const episodePadded = String(episode).padStart(2, '0')
        const seasonSector = ` S${seasonPadded} `
        const episodeSector = ` S${seasonPadded}E${episodePadded} `

        if (! releaseTitle) {
          return
        }

        if (releaseTitle.includes(seasonSector) && ! releaseTitle.includes(episodeSector)) {
          return
        }

        return {
          aps: {
            'alert': {
              'title-loc-key': `NOTIFICATION_EPISODE_${subtype}`,
              'title-loc-args': [instanceName],
              'loc-key': 'NOTIFICATION_EPISODE_DOWNLOAD_BODY',
              'loc-args': [title, season, episode],
            },
            'sound': 'ping.aiff',
            'thread-id': `series:${threadId}`,
            'relevance-score': 1.0,
            'mutable-content': 1,
          },
          eventType: payload.eventType,
          deeplink: `ruddarr://series/open/${payload.series?.id}?season=${season}&episode=${episode}&instance=${encodedInstanceName}`,
          poster: posterUrl,
        }
      }

      return {
        aps: {
          'alert': {
            'title-loc-key': `NOTIFICATION_EPISODES_${subtype}`,
            'title-loc-args': [instanceName, episodes],
            'loc-key': 'NOTIFICATION_EPISODES_DOWNLOAD_BODY',
            'loc-args': [title, season.toString()],
          },
          'sound': 'ping.aiff',
          'thread-id': `series:${threadId}`,
          'relevance-score': 1.0,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        deeplink: `ruddarr://series/open/${payload.series?.id}?season=${season}&instance=${encodedInstanceName}`,
        poster: posterUrl,
      }

    case 'ManualInteractionRequired':
      const statusMessage = payload.downloadStatusMessages?.find(
        item => item.messages && item.messages.length > 0
      )?.messages[0] ?? payload?.downloadStatusMessages?.[0].title ?? null

      return {
        aps: {
          'alert': {
            'title-loc-key': 'NOTIFICATION_MANUAL_INTERACTION_REQUIRED',
            'title-loc-args': [instanceName],
            'subtitle': statusMessage ? payload.release.releaseTitle : null,
            'body': statusMessage ? statusMessage : payload.release.releaseTitle,
          },
          'sound': 'ping.aiff',
          'thread-id': `download:${payload.downloadId}`,
          'relevance-score': 1.0,
          'mutable-content': 1,
        },
        eventType: payload.eventType,
        deeplink: 'ruddarr://activity',
      }
  }
}

async function verifyWebhookSignature(env, headers, message) {
  const auth = headers.get('Authorization') || ''
  const bearer = auth.replace(/^Basic /, '').trim()

  if (! bearer.length) {
    return false
  }

  const [_, password] = atob(bearer).split(':')

  return await verifySignature(env, password, message)
}

async function verifySignature(env, signature, message) {
  const encoder = new TextEncoder()

  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(env.WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )

  const verified = await crypto.subtle.verify(
    'HMAC',
    key,
    base64StringToArrayBuffer(signature),
    encoder.encode(message)
  )

  const days = daysSince(message.split(':')[0])

  console.info(`Signature: ${verified} (${signature}, ${message}, ${days})`)

  return verified
}

function formatIndexer(name) {
  if (name.endsWith(' (Prowlarr)')) {
    name = name.slice(0, -11);
  }

  if (name.endsWith(' (API)')) {
    name = name.slice(0, -6);
  }

  switch (name) {
    case 'BeyondHD': return 'BHD'
    case 'Blutopia': return 'BLU'
    case 'BroadcasTheNet': return 'BTN'
    case 'FileList': return 'FL'
    case 'HDBits': return 'HDB'
    case 'IPTorrents': return 'IPT'
    case 'MyAnonaMouse': return 'MAM'
    case 'PassThePopcorn': return 'PTP'
    case 'REDacted': return 'RED'
    case 'TorrentDay': return 'TD'
    case 'TorrentLeech': return 'TL'
    case 'DrunkenSlug': return 'DS'
    default: return name
  }
}

/**
 * https://github.com/tsndr/cloudflare-worker-jwt
 */
function textToBase64Url(str) {
  const encoder = new TextEncoder()
  const charCodes = encoder.encode(str)
  const binaryStr = String.fromCharCode(...charCodes)

  return btoa(binaryStr).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function arrayBufferToBase64Url(arrayBuffer) {
  return arrayBufferToBase64String(arrayBuffer).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function arrayBufferToBase64String(arrayBuffer) {
  return btoa(bytesToByteString(new Uint8Array(arrayBuffer)))
}

function bytesToByteString(bytes) {
  let byteStr = ''

  for (let i = 0; i < bytes.byteLength; i++) {
      byteStr += String.fromCharCode(bytes[i])
  }

  return byteStr
}

export function byteStringToBytes(byteStr) {
  let bytes = new Uint8Array(byteStr.length)

  for (let i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i)
  }

  return bytes
}

function textToArrayBuffer(str) {
  return byteStringToBytes(decodeURI(encodeURIComponent(str)))
}

function pemToBinary(pem) {
  return base64StringToArrayBuffer(pem.replace(/-+(BEGIN|END).*/g, '').replace(/\s/g, ''))
}

function base64StringToArrayBuffer(b64str) {
  return byteStringToBytes(atob(b64str)).buffer
}

async function sendDebugEmail(subject, payload, env) {
  await fetch('https://api.postmarkapp.com/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'content-type': 'application/json;charset=UTF-8',
      'x-postmark-server-token': env.POSTMARK_TOKEN,
    },
    body: JSON.stringify({
      'From': 'worker@till.im',
      'To': 'ruddarr@icloud.com',
      'Subject': subject,
      'TextBody': JSON.stringify(payload, null, 4)
    }),
  })
}
