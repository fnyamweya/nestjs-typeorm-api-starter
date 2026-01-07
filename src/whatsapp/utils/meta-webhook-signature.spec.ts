import {
  computeMetaSha256HexDigest,
  verifyMetaWebhookSignature,
} from './meta-webhook-signature';

describe('meta-webhook-signature', () => {
  it('verifies a valid sha256 signature', () => {
    const appSecret = 'test_secret';
    const rawBody = Buffer.from('{"hello":"world"}', 'utf8');

    const digest = computeMetaSha256HexDigest(appSecret, rawBody);
    const header = `sha256=${digest}`;

    expect(
      verifyMetaWebhookSignature({
        appSecret,
        rawBody,
        signatureHeader: header,
      }),
    ).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const appSecret = 'test_secret';
    const rawBody = Buffer.from('{"hello":"world"}', 'utf8');

    expect(
      verifyMetaWebhookSignature({
        appSecret,
        rawBody,
        signatureHeader: 'sha256=deadbeef',
      }),
    ).toBe(false);
  });

  it('rejects non-sha256 algorithm', () => {
    const appSecret = 'test_secret';
    const rawBody = Buffer.from('x', 'utf8');

    const digest = computeMetaSha256HexDigest(appSecret, rawBody);

    expect(
      verifyMetaWebhookSignature({
        appSecret,
        rawBody,
        signatureHeader: `sha1=${digest}`,
      }),
    ).toBe(false);
  });

  it('rejects sha256 digest with wrong length', () => {
    const appSecret = 'test_secret';
    const rawBody = Buffer.from('x', 'utf8');

    expect(
      verifyMetaWebhookSignature({
        appSecret,
        rawBody,
        signatureHeader: 'sha256=deadbeef',
      }),
    ).toBe(false);
  });
});
