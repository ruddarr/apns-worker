import { defineConfig } from 'vite'
import { sentryVitePlugin } from '@sentry/vite-plugin'

export default defineConfig({
	build: {
		lib: {
			entry: 'src/worker.js',
			formats: ['es'],
			fileName: () => 'worker.js',
		},
		sourcemap: true,
		target: 'es2022',
		outDir: 'dist',
		minify: false,
		rollupOptions: {
			external: (id) => id.startsWith('node:'),
		},
	},
	plugins: [
		process.env.SENTRY_AUTH_TOKEN && sentryVitePlugin({
			authToken: process.env.SENTRY_AUTH_TOKEN,
			org: process.env.SENTRY_ORG,
			project: process.env.SENTRY_PROJECT,
		}),
	].filter(Boolean),
})
