import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
    plugins: [
        cloudflareTest(async () => ({
            wrangler: {
                configPath: './wrangler.toml',
            },
            miniflare: {
                bindings: {
                    TEST_MIGRATIONS: await readD1Migrations('./drizzle'),
                    SSO_OIDC_RUNTIME_SECRET: 'runtime-oidc-test-secret',
                    VAULT_BASE_URL: 'https://vault.example.com',
                    DUO_CONFIG_ENCRYPTION_KEY: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
                    HEALTH_CHECK_TOKEN: 'integration-health-check-token',
                },
            },
        })),
    ],
    test: {
        include: ['test/**/*.test.ts'],
        setupFiles: ['./test/setup.ts'],
    },
});
