import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker, { buildNotificationPayload } from '../src/worker';
import episodeFileDelete from '../payloads/series-episode-file-delete.json';

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
});

describe('buildNotificationPayload', () => {
	it('sends the series, season and episode for a deleted episode file', () => {
		const { aps } = buildNotificationPayload({ ...episodeFileDelete, instanceName: 'Sonarr' });

		expect(aps.alert['loc-key']).toBe('NOTIFICATION_EPISODE_FILE_DELETED_BODY');
		expect(aps.alert['loc-args']).toEqual(['The New Pope', '1', '1']);
	});
});
