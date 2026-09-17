// Secrets are set with `wrangler secret put`, not in wrangler.jsonc, so
// `wrangler types` cannot see them. This merges into the generated Env.
interface Env {
  REGISTER_TOKEN?: string;
}
