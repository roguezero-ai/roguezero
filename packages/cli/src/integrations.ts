/**
 * Starter pack — a small, curated set of popular integrations, shipped as security-reviewed,
 * least-privilege tool definitions. NOT a catalog: this is a fixed, reviewed set we treat like
 * product (pinned API versions, minimal scopes documented), and the long tail is a user's own
 * `registry.json` (three lines) or a future community gallery — never an open-ended, us-maintained
 * catalog race (see PRODUCT-THESIS §5.1 / §9).
 *
 * `roguezero add <id>` scaffolds these into a runtime workspace and stores the one credential each
 * needs — so a stranger goes from an empty runtime to "my agent uses GitHub without holding my
 * token" in one command. Each integration ships ONE high-value tool for now (the vault binds a
 * credential to a single tool id); multi-tool integrations are a fast-follow.
 *
 * Everything here rides the already-shipped static-credential path (bearer token in the vault) — no
 * OAuth. Delegated-OAuth integrations (the Google suite, etc.) wait on the consent-flow
 * productization (the `spike/oauth2-credential-provider` promotion).
 */

export interface IntegrationTool {
  id: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  scheme: "https";
  host: string;
  path: string;
  params?: Array<Record<string, unknown>>;
  /** Static operator headers a real API demands (Accept, User-Agent, API version). */
  headers?: Record<string, string>;
  /** A nested JSON body with `{param}` placeholders — for APIs whose payload isn't a flat object. */
  bodyTemplate?: unknown;
  credential: { ref: string; placement: "bearer" | "basic" | "header"; header?: string };
}

export interface Integration {
  id: string;
  name: string;
  description: string;
  /** Where to create the credential. */
  docsUrl: string;
  /** The one credential this integration needs, and least-privilege guidance for it. */
  secret: { label: string; help: string };
  tools: IntegrationTool[];
}

const github: Integration = {
  id: "github",
  name: "GitHub",
  description: "File issues on a repo — your agent acts, and never holds your token.",
  docsUrl: "https://github.com/settings/tokens",
  secret: {
    label: "GitHub token",
    help: "Create a fine-grained personal access token scoped to only the target repo, with Issues: Read and write. Least privilege — never a classic token with `repo`.",
  },
  tools: [
    {
      id: "github_create_issue",
      method: "POST",
      scheme: "https",
      host: "api.github.com",
      path: "/repos/{owner}/{repo}/issues",
      headers: {
        accept: "application/vnd.github+json",
        "user-agent": "roguezero",
        "x-github-api-version": "2022-11-28",
      },
      params: [
        { name: "owner", in: "path", required: true },
        { name: "repo", in: "path", required: true },
        { name: "title", in: "body", required: true },
        { name: "body", in: "body" },
      ],
      credential: { ref: "github-token", placement: "bearer" },
    },
  ],
};

const slack: Integration = {
  id: "slack",
  name: "Slack",
  description: "Post a message to a channel — the bot token stays in the vault, not the agent.",
  docsUrl: "https://api.slack.com/apps",
  secret: {
    label: "Slack bot token (xoxb-…)",
    help: "Create a Slack app, add the `chat:write` bot scope, install it to your workspace, and copy the Bot User OAuth Token. Grant only the channels the agent needs.",
  },
  tools: [
    {
      id: "slack_post_message",
      method: "POST",
      scheme: "https",
      host: "slack.com",
      path: "/api/chat.postMessage",
      params: [
        { name: "channel", in: "body", required: true },
        { name: "text", in: "body", required: true },
      ],
      credential: { ref: "slack-token", placement: "bearer" },
    },
  ],
};

const stripe: Integration = {
  id: "stripe",
  name: "Stripe",
  description: "Read recent charges — a read-only key, injected server-side, never in the agent.",
  docsUrl: "https://dashboard.stripe.com/apikeys",
  secret: {
    label: "Stripe secret key (sk_… or rk_…)",
    help: "Use a RESTRICTED key (rk_…) with Charges: Read only. Never a full secret key — the agent should read, not move money.",
  },
  tools: [
    {
      id: "stripe_list_charges",
      method: "GET",
      scheme: "https",
      host: "api.stripe.com",
      path: "/v1/charges",
      headers: { "stripe-version": "2024-06-20" },
      params: [{ name: "limit", in: "query", type: "number" }],
      credential: { ref: "stripe-key", placement: "bearer" },
    },
  ],
};

const notion: Integration = {
  id: "notion",
  name: "Notion",
  description: "Search your workspace — the integration token stays vaulted, not in the agent.",
  docsUrl: "https://www.notion.so/my-integrations",
  secret: {
    label: "Notion internal integration token (secret_…)",
    help: "Create an internal integration, give it read access, and share only the pages/databases the agent needs. Copy the Internal Integration Secret.",
  },
  tools: [
    {
      id: "notion_search",
      method: "POST",
      scheme: "https",
      host: "api.notion.com",
      path: "/v1/search",
      headers: { "notion-version": "2022-06-28" }, // Notion rejects a request without it
      params: [{ name: "query", in: "body" }],
      credential: { ref: "notion-token", placement: "bearer" },
    },
  ],
};

const sentry: Integration = {
  id: "sentry",
  name: "Sentry",
  description: "List an org's issues — a read-only auth token, injected server-side.",
  docsUrl: "https://sentry.io/settings/account/api/auth-tokens/",
  secret: {
    label: "Sentry auth token",
    help: "Create an auth token scoped to `event:read` / `project:read` only. Least privilege — the agent reads issues, it doesn't administer the org.",
  },
  tools: [
    {
      id: "sentry_list_issues",
      method: "GET",
      scheme: "https",
      host: "sentry.io",
      path: "/api/0/organizations/{org}/issues/",
      params: [
        { name: "org", in: "path", required: true },
        { name: "query", in: "query" },
      ],
      credential: { ref: "sentry-token", placement: "bearer" },
    },
  ],
};

const hubspot: Integration = {
  id: "hubspot",
  name: "HubSpot",
  description: "List CRM contacts — the private-app token never reaches the agent.",
  docsUrl: "https://developers.hubspot.com/docs/api/private-apps",
  secret: {
    label: "HubSpot private app token (pat-…)",
    help: "Create a private app and grant only `crm.objects.contacts.read`. Least privilege — read contacts, nothing else.",
  },
  tools: [
    {
      id: "hubspot_list_contacts",
      method: "GET",
      scheme: "https",
      host: "api.hubapi.com",
      path: "/crm/v3/objects/contacts",
      params: [{ name: "limit", in: "query", type: "number" }],
      credential: { ref: "hubspot-token", placement: "bearer" },
    },
  ],
};

const airtable: Integration = {
  id: "airtable",
  name: "Airtable",
  description: "List records from a table — a scoped PAT, injected, never held by the agent.",
  docsUrl: "https://airtable.com/create/tokens",
  secret: {
    label: "Airtable personal access token (pat…)",
    help: "Create a PAT scoped to `data.records:read` on only the base(s) the agent needs. Least privilege — read records, not schema or other bases.",
  },
  tools: [
    {
      id: "airtable_list_records",
      method: "GET",
      scheme: "https",
      host: "api.airtable.com",
      path: "/v0/{base}/{table}",
      params: [
        { name: "base", in: "path", required: true },
        { name: "table", in: "path", required: true },
        { name: "maxRecords", in: "query", type: "number" },
      ],
      credential: { ref: "airtable-token", placement: "bearer" },
    },
  ],
};

const openai: Integration = {
  id: "openai",
  name: "OpenAI",
  description: "Ask a model — your API key is injected server-side, never held by the agent.",
  docsUrl: "https://platform.openai.com/api-keys",
  secret: {
    label: "OpenAI API key (sk-…)",
    help: "Use a project key scoped to only the models you need, with a spend limit. The agent calls the model; it never sees the key.",
  },
  tools: [
    {
      id: "openai_chat",
      method: "POST",
      scheme: "https",
      host: "api.openai.com",
      path: "/v1/chat/completions",
      // Nested payload via bodyTemplate — the agent fills only the leaf slots (model, prompt).
      bodyTemplate: {
        model: "{model}",
        messages: [{ role: "user", content: "{prompt}" }],
        max_tokens: 1024,
      },
      params: [
        {
          name: "model",
          in: "body",
          type: "enum",
          enum: ["gpt-4o-mini", "gpt-4o"],
          required: true,
        },
        { name: "prompt", in: "body", required: true },
      ],
      credential: { ref: "openai-key", placement: "bearer" },
    },
  ],
};

/**
 * The curated starter pack, by id. Deliberately small and reviewed.
 *
 * `openai_chat` uses a `bodyTemplate` (nested JSON payload); the same mechanism now makes
 * GraphQL (Linear) and other nested-body APIs shippable as future entries — added deliberately,
 * one reviewed tool at a time, never an open-ended catalog.
 */
export const INTEGRATIONS: Record<string, Integration> = {
  github,
  slack,
  stripe,
  notion,
  sentry,
  hubspot,
  airtable,
  openai,
};

export function getIntegration(id: string): Integration | undefined {
  return INTEGRATIONS[id];
}

export function listIntegrations(): Integration[] {
  return Object.values(INTEGRATIONS);
}
