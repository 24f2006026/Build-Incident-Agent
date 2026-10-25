# Observable Incident Agent — zero-dollar deployment

A receipt-driven incident agent implementing the `ga5-incident-agent/v2` HTTP contract. It persists run/receipt snapshots, sends one model-planning request per new `runId`, validates catalog tools and permitted effects, handles one 503 retry, suppresses effects after diagnostic failures/timeouts, gates destructive actions on explicit approval, and stores OTLP-compatible trace JSON.

## Routes

- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`
- `GET /healthz`

The service never receives or performs real production-tool calls. It returns dispatch intents and advances only when the grader posts authoritative receipts. The `sensitive` request object is never sent to the model or persisted as cleartext. Prompts, transcripts, tool arguments/results, and credentials are omitted from telemetry.

## Free deployment setup

This configuration uses a Render free web service, Neon free Postgres, and the free tier of the Gemini API. It does not provision a paid Render web service or Render database.

### 1. Upload the source to GitHub

1. Download and extract this ZIP.
2. Create a new repository at <https://github.com/new>.
3. Upload the *contents* of the extracted `observable-incident-agent` folder so `render.yaml`, `Dockerfile`, `app.py`, and `requirements.txt` are at the repository root.

### 2. Create a free Neon Postgres database

1. Create a free project at <https://neon.tech/>.
2. Copy its Postgres connection string. Prefer Neon's pooled connection string if the dashboard offers one.
3. Keep the connection string private; do not put it in GitHub.

The app accepts standard `postgresql://...` URLs and uses TLS settings present in the provider's connection string. The database stores run and receipt replay state. Do not use Render's free Postgres for a lasting database: Render currently expires its free Postgres instances after 30 days.

### 3. Get a Gemini API key on the free tier

1. Open <https://aistudio.google.com/apikey>.
2. Create an API key for a project eligible for the Gemini API free tier.
3. Do not add a payment method or enable paid API billing if your requirement is strictly $0. Google can restrict free-tier eligibility or quotas for some accounts/projects.

The project uses Gemini's OpenAI-compatible Chat Completions endpoint. The Render variable named `OPENAI_API_KEY` is where you paste the Gemini API key; it is only an environment-variable name for compatibility. The configured model is `gemini-3.8-flash`, and the base URL is `https://generativelanguage.googleapis.com/v1beta/openai`.

**Free-tier privacy note:** Google documents that content submitted through the Gemini API free tier may be used to improve its products. This assignment uses synthetic incidents; do not send real production logs, credentials, or personal data.

### 4. Deploy from GitHub on Render

1. Open <https://dashboard.render.com/>.
2. Choose **New → Blueprint** and connect the GitHub repository.
3. Review the service: `render.yaml` specifies `plan: free` and has no paid database resource.
4. In the web service's Environment settings, set:
   - `OPENAI_API_KEY`: your Gemini API key from step 3
   - `DATABASE_URL`: your Neon Postgres connection string from step 2
5. Deploy/redeploy and wait for a successful health check.

Open `https://YOUR-SERVICE.onrender.com/healthz`. A healthy service returns `{"ok":true,"service":"observable-incident-agent"}`. Submit the base URL `https://YOUR-SERVICE.onrender.com`, without `/healthz`, `/v2/incidents`, a query string, or a fragment.

## Free-tier caveats

- Render free web services spin down after 15 minutes without inbound traffic; waking one can take about a minute. That can exceed the grader's per-request deadline if its first request arrives while the service is asleep. Before submitting, visit `/healthz` to wake the service and submit promptly. This reduces, but cannot eliminate, the risk of a grader request arriving after the service sleeps.
- Render free services have an ephemeral filesystem; state must be stored in the external Neon database as configured above.
- Neon free compute scales to zero after inactivity, so the first database connection after a quiet period may be slower. Stay within its free storage/compute/network quotas.
- Gemini free tier has model-specific rate limits and availability requirements. Confirm `gemini-3.8-flash` appears in your AI Studio project and the free quota is enabled before running the grader.
- These free tiers are best-effort hobby tiers, not production reliability guarantees. This deployment is $0 only while you remain within free quotas and do not enable paid upgrades or billing.

## Local tests

Install dependencies, then run:

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

The test suite exercises replay and content conflicts, approval digests, 503 retries, timeout suppression, redaction, and trace correlation.

## Behavior and state rules

- Exact `runId` request replays return the original create response. Changed request content for the same ID returns 409.
- Exact receipt replays return the original receipt response. Reusing a `receiptId` with different content returns 409.
- Receipt processing and `GET` never call the model. The model is called once for each first-seen valid run.
- A 503 creates exactly one retry for that logical call, with the same action/call IDs and a new CLIENT span ID. A second 503 fails the action.
- A diagnostic timeout (`status: 0`, `errorType: "timeout"`) or failed/unconfirmed diagnostics suppress the planned effect.
- `rollback_deployment` and `disable_feature` always require approval; other tools listed in `approvalRequiredFor` are also gated. The approval digest is SHA-256 of recursively sorted compact JSON arguments.
- OTLP includes the SERVER, agent INTERNAL, model CLIENT, logical tool spans and per-attempt CLIENT spans, plus `incident.join` for diagnostic fan-out and `approval_gate` for gated effects. Trace attributes never include prompts, transcripts, tool arguments/results, authorization credentials, or the input `sensitive` object.

## Other providers

The planner uses an OpenAI-compatible Chat Completions endpoint. `OPENAI_BASE_URL` and `OPENAI_MODEL` can be changed for another compatible provider. Check that your selected provider's free tier can handle the input size and request limits before using it.
