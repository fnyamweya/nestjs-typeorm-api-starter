import * as crypto from 'node:crypto';

export function parseMetaSignatureHeader(signatureHeader: string): {
  algorithm: string;
  hexDigest: string;
} | null {
  // Meta sends: "sha256=<hex>" in X-Hub-Signature-256
  // We enforce the exact sha256 hex length (64 chars) to avoid accepting malformed digests.
  const trimmed = signatureHeader.trim();
  const match = /^sha256=([0-9a-fA-F]{64})$/.exec(trimmed);
  if (!match) return null;

  return { algorithm: 'sha256', hexDigest: match[1].toLowerCase() };
}

export function computeMetaSha256HexDigest(
  appSecret: string,
  rawBody: Buffer,
): string {
  return crypto.createHmac('sha256', appSecret).update(rawBody).digest('hex');
}

export function verifyMetaWebhookSignature(params: {
  appSecret: string;
  rawBody: Buffer;
  signatureHeader: string;
}): boolean {
  const parsed = parseMetaSignatureHeader(params.signatureHeader);
  if (!parsed) return false;

  const expectedHex = computeMetaSha256HexDigest(
    params.appSecret,
    params.rawBody,
  );

  // Constant-time compare
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  const providedBuf = Buffer.from(parsed.hexDigest, 'hex');
  if (expectedBuf.length !== providedBuf.length) return false;

  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}
