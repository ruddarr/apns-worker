import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/worker';

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
