import { execSync } from 'child_process';
import * as net from 'net';
import * as path from 'path';

function canConnect(host: string, port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const onDone = (ok: boolean) => {
      socket.removeAllListeners();
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      resolve(ok);
    };

    socket.setTimeout(timeoutMs);
    socket.once('error', () => onDone(false));
    socket.once('timeout', () => onDone(false));
    socket.connect(port, host, () => onDone(true));
  });
}

async function waitForPort(host: string, port: number, totalMs = 30000): Promise<void> {
  const started = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (await canConnect(host, port)) return;
    if (Date.now() - started > totalMs) {
      throw new Error(`Timed out waiting for ${host}:${port}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
}

export default async function globalSetup() {
  // E2E tests expect Postgres + Redis. If they aren't running, start them via docker-compose.
  const pgHost = process.env.E2E_DB_HOST ?? process.env.DB_HOST ?? 'localhost';
  const pgPort = Number(process.env.E2E_DB_PORT ?? process.env.DB_PORT ?? '5432');
  const redisHost = process.env.E2E_REDIS_HOST ?? process.env.REDIS_HOST ?? 'localhost';
  const redisPort = Number(process.env.E2E_REDIS_PORT ?? process.env.REDIS_PORT ?? '6379');

  const hasPg = await canConnect(pgHost, pgPort);
  const hasRedis = await canConnect(redisHost, redisPort);

  if (hasPg && hasRedis) return;

  // Start dependencies (only if they aren't already reachable).
  const cwd = path.resolve(__dirname, '../..');
  execSync('docker compose up -d db redis', { cwd, stdio: 'inherit' });

  // Wait for them to be reachable on localhost-published ports.
  await waitForPort(pgHost, pgPort, 60000);
  await waitForPort(redisHost, redisPort, 60000);
}
