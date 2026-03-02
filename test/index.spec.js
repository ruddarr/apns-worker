import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/worker';

const testPayload = JSON.stringify({ eventType: 'Test' });

describe('webhook signature validation', () => {
	it('returns 400 for an invalid base64 URL path', async () => {
		const request = new Request('http://example.com/push/!!!invalid!!!', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: testPayload,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(400);
	});

	it('returns 403 for an invalid base64 Authorization header', async () => {
		const validPath = btoa('1700000001:a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5');
		const request = new Request(`http://example.com/push/${validPath}`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': 'Basic !!!invalid base64!!!',
			},
			body: testPayload,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(403);
	});

	it('returns 403 for an invalid base64 signature in Authorization header', async () => {
		const validPath = btoa('1700000001:a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5');
		const bearerWithMalformedSignature = btoa('user:!!!invalid base64 signature!!!');
		const request = new Request(`http://example.com/push/${validPath}`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Basic ${bearerWithMalformedSignature}`,
			},
			body: testPayload,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(403);
	});
});
