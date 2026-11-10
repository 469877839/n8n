import { UserError } from 'n8n-workflow';

import { markNonRetryable } from '../http/retryability';

export type SsrfBlockedUrlReason = 'scheme' | 'port';

/**
 * Error thrown when a destination URL is denied by SSRF scheme or port policy.
 */
export class SsrfBlockedUrlError extends UserError {
	readonly reason: SsrfBlockedUrlReason;

	constructor(
		reason: SsrfBlockedUrlReason,
		readonly value: string,
	) {
		super(
			reason === 'scheme'
				? 'The request was blocked because the URL scheme is not allowed'
				: 'The request was blocked because the destination port is not allowed',
			{
				description:
					reason === 'scheme'
						? `The scheme '${value}' is not on the configured list of allowed schemes. ` +
							'Ask your n8n administrator to adjust the allowed schemes in the environment configuration.'
						: `The port '${value}' is not on the configured list of allowed ports. ` +
							'Ask your n8n administrator to adjust the allowed ports in the environment configuration.',
				extra: { reason, value },
			},
		);

		this.name = 'SsrfBlockedUrlError';
		this.reason = reason;
		markNonRetryable(this);
	}
}
