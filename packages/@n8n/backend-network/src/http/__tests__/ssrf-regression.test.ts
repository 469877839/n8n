import type { Logger } from '@n8n/backend-common';
import { SsrfProtectionConfig } from '@n8n/config';
import { AxiosError } from 'axios';
import { OperationalError, UserError } from 'n8n-workflow';
import type { LookupAddress } from 'node:dns';
import { gzipSync } from 'node:zlib';
import { mock } from 'vitest-mock-extended';

import type { DnsResolver } from '../../dns';
import { SsrfBlockedIpError } from '../../ssrf/ssrf-blocked-ip.error';
import { SsrfBlockedUrlError } from '../../ssrf/ssrf-blocked-url.error';
import { SsrfProtectionService } from '../../ssrf/ssrf-protection.service';
import { useCleanProxyEnv } from '../../ssrf/__tests__/mock-ssrf-bridge';
import { type LocalServer, startServer } from '../local-server';
import { OutboundHttp } from '../outbound-http';
import { HttpResponseSizeLimitError } from '../response-size-limit.error';

// SSRF regression suite. Every test runs the real SsrfProtectionService (real
// URL parsing, real net.BlockList IP checks) in front of the real request
// pipeline against a real local server. DNS is the only stubbed boundary:
// these tests never reach a nameserver, and no test stubs the guard itself.

function createConfig(overrides: Partial<SsrfProtectionConfig> = {}): SsrfProtectionConfig {
	const config = new SsrfProtectionConfig();
	Object.assign(config, overrides);
	return config;
}

function createMockDnsResolver(entries: Record<string, LookupAddress[]> = {}) {
	const resolver = mock<DnsResolver>();
	resolver.lookup.mockImplementation(async (hostname) => entries[hostname] ?? []);
	return resolver;
}

function createService(
	configOverrides: Partial<SsrfProtectionConfig> = {},
	dnsResolver?: ReturnType<typeof createMockDnsResolver>,
) {
	const scopedLogger = mock<Logger>();
	const logger = mock<Logger>({ scoped: vi.fn().mockReturnValue(scopedLogger) });
	return new SsrfProtectionService(
		createConfig(configOverrides),
		dnsResolver ?? createMockDnsResolver(),
		logger,
	);
}

/** A guarded request client wired like production: real service, protection enabled. */
function createGuardedClient(service: SsrfProtectionService) {
	return new OutboundHttp(service, createConfig({ enabled: true }), mock<Logger>()).requests();
}

/** Loopback is carved out of the block list so a request can reach the local test server. */
const LOOPBACK_CARVE_OUT: Partial<SsrfProtectionConfig> = {
	allowedIpRanges: ['127.0.0.0/8'] as unknown as SsrfProtectionConfig['allowedIpRanges'],
	allowedPorts: [],
};

useCleanProxyEnv();

/** Walks the `cause` chain to find an error of the given class. */
function causeChainIncludes(error: unknown, errorClass: new (...args: never[]) => Error): boolean {
	let current = error;
	for (let depth = 0; depth < 5 && current instanceof Error; depth++) {
		if (current instanceof errorClass) return true;
		current = (current as { cause?: unknown }).cause;
	}
	return false;
}

describe('SSRF regression (real service, real server)', () => {
	describe('allowed and denied addresses', () => {
		let server: LocalServer;

		beforeEach(async () => {
			server = await startServer((_req, res) => {
				res.writeHead(200, { 'content-type': 'text/plain' });
				res.end('ok');
			});
		});

		afterEach(async () => {
			await server.close();
		});

		it('allows an explicitly allow-listed address through the guarded path', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			await expect(client.request({ method: 'GET', url: server.url })).resolves.toBe('ok');
			expect(server.captured).toEqual(['/']);
		});

		it('blocks a loopback target before any connection is made', async () => {
			const client = createGuardedClient(createService({ allowedPorts: [] }));

			const rejection = await client
				.request({ method: 'GET', url: server.url })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(SsrfBlockedIpError);
			expect(rejection).toBeInstanceOf(UserError);
			expect(server.captured).toEqual([]);
		});

		it('blocks a disallowed scheme before any connection is made', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			const rejection = await client
				.request({ method: 'GET', url: 'ftp://127.0.0.1:21/' })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(SsrfBlockedUrlError);
			expect((rejection as SsrfBlockedUrlError).reason).toBe('scheme');
			expect(server.captured).toEqual([]);
		});

		it('blocks a disallowed port before any connection is made', async () => {
			// Default port policy allows only 80 and 443; the test server listens elsewhere.
			const client = createGuardedClient(
				createService({
					allowedIpRanges: LOOPBACK_CARVE_OUT.allowedIpRanges,
				}),
			);

			const rejection = await client
				.request({ method: 'GET', url: server.url })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(SsrfBlockedUrlError);
			expect((rejection as SsrfBlockedUrlError).reason).toBe('port');
			expect(server.captured).toEqual([]);
		});
	});

	describe('redirects and DNS changes', () => {
		let server: LocalServer;
		let serverUrl = '';

		const portOf = (url: string) => new URL(url).port;

		beforeEach(async () => {
			// A proxy is configured so the manual redirect follower engages and
			// re-validates every hop; NO_PROXY keeps the loopback connection direct.
			process.env.HTTP_PROXY = 'http://127.0.0.1:1';
			process.env.HTTPS_PROXY = 'http://127.0.0.1:1';
			process.env.NO_PROXY = '127.0.0.1,localhost,rebind.test';

			server = await startServer((req, res) => {
				if (req.url === '/to-metadata') {
					res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data' });
					res.end();
					return;
				}
				if (req.url === '/to-rebind') {
					res.writeHead(302, { Location: `http://rebind.test:${portOf(serverUrl)}/internal` });
					res.end();
					return;
				}
				res.writeHead(200, { 'content-type': 'text/plain' });
				res.end(`reached:${req.url}`);
			});
			serverUrl = server.url;
		});

		afterEach(async () => {
			await server.close();
		});

		it('re-validates every redirect hop and blocks a redirect to a link-local target', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			const rejection = await client
				.request({ method: 'GET', url: `${serverUrl}/to-metadata` })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(SsrfBlockedIpError);
			expect(server.captured).toEqual(['/to-metadata']);
		});

		it('blocks a redirect when the target re-resolves to a private address', async () => {
			// The hostname resolves to loopback for the first hop, then the answer
			// changes to a private address when the redirect target is re-validated.
			const answers: LookupAddress[][] = [
				[{ address: '127.0.0.1', family: 4 }],
				[{ address: '127.0.0.1', family: 4 }],
				[{ address: '10.0.0.1', family: 4 }],
			];
			const dnsResolver = createMockDnsResolver();
			dnsResolver.lookup.mockImplementation(async () => answers.shift() ?? []);
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT, dnsResolver));

			const rejection = await client
				.request({ method: 'GET', url: `http://rebind.test:${portOf(serverUrl)}/to-rebind` })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(SsrfBlockedIpError);
			expect(server.captured).toEqual(['/to-rebind']);
			// Pre-flight, connect-time, and the redirect hop each resolved again.
			expect(dnsResolver.lookup.mock.calls.length).toBeGreaterThanOrEqual(3);
		});

		it('blocks at connect time when the address changes after the pre-flight check', async () => {
			// DNS rebinding (TOCTOU): the pre-flight answer is loopback (allowed by
			// the carve-out), but the connect-time lookup returns a private address.
			const answers: LookupAddress[][] = [
				[{ address: '127.0.0.1', family: 4 }],
				[{ address: '10.0.0.1', family: 4 }],
			];
			const dnsResolver = createMockDnsResolver();
			dnsResolver.lookup.mockImplementation(async () => answers.shift() ?? []);
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT, dnsResolver));

			const rejection = await client
				.request({ method: 'GET', url: `http://rebind.test:${portOf(serverUrl)}/` })
				.catch((error: unknown) => error);

			// A connect-time rejection surfaces as an AxiosError whose cause is the block.
			expect(causeChainIncludes(rejection, SsrfBlockedIpError)).toBe(true);
			expect(server.captured).toEqual([]);
		});
	});

	describe('response limits and timeouts', () => {
		let server: LocalServer;

		beforeEach(async () => {
			server = await startServer((req, res) => {
				if (req.url === '/slow') {
					const timer = setTimeout(() => res.end('late'), 2000);
					timer.unref();
					req.socket.on('close', () => clearTimeout(timer));
					return;
				}
				if (req.url === '/large') {
					res.writeHead(200, { 'content-type': 'text/plain' });
					res.end('x'.repeat(256 * 1024));
					return;
				}
				if (req.url === '/gzip-large') {
					res.writeHead(200, {
						'content-type': 'text/plain',
						'content-encoding': 'gzip',
					});
					res.end(gzipSync('x'.repeat(256 * 1024)));
					return;
				}
				if (req.url === '/gzip-small') {
					res.writeHead(200, {
						'content-type': 'text/plain',
						'content-encoding': 'gzip',
					});
					res.end(gzipSync('hello'));
					return;
				}
				res.writeHead(404);
				res.end();
			});
		});

		afterEach(async () => {
			await server.close();
		});

		it('aborts a response that exceeds the read timeout', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			const rejection = await client
				.request({ method: 'GET', url: `${server.url}/slow`, timeout: 50 })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(AxiosError);
			expect((rejection as AxiosError).code).toBe('ECONNABORTED');
			expect(server.captured).toEqual(['/slow']);
		});

		it('rejects a response larger than the configured limit', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			const rejection = await client
				.request({ method: 'GET', url: `${server.url}/large`, maxResponseBodyBytes: 1024 })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(HttpResponseSizeLimitError);
			expect(rejection).toBeInstanceOf(OperationalError);
			expect((rejection as HttpResponseSizeLimitError).code).toBe('ERR_RESPONSE_TOO_LARGE');
		});

		it('applies the size limit to decompressed bytes', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			const rejection = await client
				.request({ method: 'GET', url: `${server.url}/gzip-large`, maxResponseBodyBytes: 1024 })
				.catch((error: unknown) => error);

			expect(rejection).toBeInstanceOf(HttpResponseSizeLimitError);
		});

		it('decodes a compressed response within the limit', async () => {
			const client = createGuardedClient(createService(LOOPBACK_CARVE_OUT));

			await expect(
				client.request({
					method: 'GET',
					url: `${server.url}/gzip-small`,
					maxResponseBodyBytes: 1024,
				}),
			).resolves.toBe('hello');
		});
	});
});
