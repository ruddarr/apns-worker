import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker, { buildNotificationPayload } from '../src/worker';
import episodeFileDelete from '../payloads/series-episode-file-delete.json';
import manualInteraction from '../payloads/series-interaction-required.json';

describe('worker', () => {
	it('returns 400 for request with empty body', async () => {
		const request = new Request('http://example.com', { method: 'POST' });
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		const body = await response.json();
		expect(response.status).toBe(400);
		expect(body.message).toBe('invalid JSON body');
	});

	it('returns 400 for request with invalid JSON body', async () => {
		const request = new Request('http://example.com', {
			method: 'POST',
			body: 'not json',
			headers: { 'content-type': 'application/json' },
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		const body = await response.json();
		expect(response.status).toBe(400);
		expect(body.message).toBe('invalid JSON body');
	});

	it('returns 400 for request with valid JSON but invalid path', async () => {
		const request = new Request('http://example.com/unknown', {
			method: 'POST',
			body: JSON.stringify({ eventType: 'Test' }),
			headers: { 'content-type': 'application/json' },
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
	});

	async function webhook(authorization) {
		const request = new Request(`http://example.com/push/${btoa('1700000001:' + 'a'.repeat(32))}`, {
			method: 'POST',
			body: JSON.stringify({ eventType: 'Grab' }),
			headers: { 'content-type': 'application/json', authorization },
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(request, { ...env, WEBHOOK_SECRET: 'secret' }, ctx);
		await waitOnExecutionContext(ctx);

		return { status: response.status, body: await response.json() };
	}

	it('returns 403 for a webhook signature that is not valid base64', async () => {
		const { status, body } = await webhook(`Basic ${btoa('ruddarr:not*valid*base64')}`);
		expect(status).toBe(403);
		expect(body.message).toBe('invalid webhook signature');
	});

	it('returns 403 for webhook credentials without a password', async () => {
		const { status, body } = await webhook(`Basic ${btoa('ruddarr')}`);
		expect(status).toBe(403);
		expect(body.message).toBe('invalid webhook signature');
	});

	it('returns 403 for a webhook Authorization header that is not valid base64', async () => {
		const { status, body } = await webhook('Basic !!!');
		expect(status).toBe(403);
		expect(body.message).toBe('invalid webhook signature');
	});

	it('accepts a valid webhook signature', async () => {
		const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
		const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`1700000001:${'a'.repeat(32)}`));
		const signature = btoa(String.fromCharCode(...new Uint8Array(mac)));

		const { status, body } = await webhook(`Basic ${btoa(`ruddarr:${signature}`)}`);
		expect(status).toBe(410);
		expect(body.message).toBe('webhook URL expired');
	});
});

describe('buildNotificationPayload', () => {
	it('sends the series, season and episode for a deleted episode file', () => {
		const { aps } = buildNotificationPayload({ ...episodeFileDelete, instanceName: 'Sonarr' });

		expect(aps.alert['loc-key']).toBe('NOTIFICATION_EPISODE_FILE_DELETED_BODY');
		expect(aps.alert['loc-args']).toEqual(['The New Pope', '1', '1']);
	});

	it('falls back to the release title when a manual interaction has no status messages', () => {
		const { aps } = buildNotificationPayload({ ...manualInteraction, downloadStatusMessages: [] });

		expect(aps.alert.subtitle).toBeNull();
		expect(aps.alert.body).toBe(manualInteraction.release.releaseTitle);
	});
});
