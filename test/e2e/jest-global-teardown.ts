export default async function globalTeardown() {
  // Intentionally no-op.
  // We don't automatically shut down docker-compose services because they may be shared
  // with other tests or a developer's local environment.
}
