# Apify YouTube Resolver Actor

This project contains a lightweight HTTP server (`server.mjs`) that resolves streaming-friendly
media URLs (including HLS manifests) using `yt-dlp` and proxies them through the actor. It is
intended to run inside an [Apify](https://apify.com) actor.

## Prerequisites

- Node.js 18 or newer locally (matches the default Apify Node.js image).
- [`apify-cli`](https://docs.apify.com/platform/actors/running#apify-cli) installed globally:
  ```bash
  npm install -g apify-cli
  ```
- An Apify account. Run `apify login` and follow the browser prompt if you have not authenticated
yet.

## Environment variables

The server reads several optional environment variables when it starts inside Apify:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SIGN_SECRET` | Secret used to HMAC-sign temporary proxy tokens. Change this in production. | `CHANGE_ME` |
| `TOKEN_TTL_SEC` | How long signed proxy URLs stay valid. | `300` |
| `UPSTREAM_TIMEOUT_MS` | Total timeout for requests to upstream CDNs. | `25000` |
| `UPSTREAM_INACTIVITY_MS` | How long to wait for new data before aborting an upstream stream. Set higher for long videos. | Half of `UPSTREAM_TIMEOUT_MS`, minimum `8000` |
| `AUTO_EXIT_IDLE_MS` | Optional auto-exit when no requests arrive (helps scale-to-zero). | Disabled |
| `CORS_ALLOW` | Allowed origin(s) for browser requests. | `*` |
| `PROXY_PARAM` | Query parameter name that carries the signed token. | `sig` |
| `HLS_TOKEN_TTL_SEC` | TTL for re-signed playlist segments. | `1800` |

You can configure these on the actor's *Settings → Environment variables* page in the Apify
console after you publish the actor.

## Local development

To test locally you can run:

```bash
npm install
node server.mjs
```

The server listens on the port specified by `ACTOR_WEB_SERVER_PORT`, `PORT`, or `8080` by default.

## Publishing to Apify

1. **Ensure the actor metadata file is present**: The provided `apify.json` describes the actor name
   and build command. Adjust the `name` field if you want to publish under a different actor name.
2. **Authenticate** (once per machine):
   ```bash
   apify login
   ```
3. **Install dependencies and build** (handled automatically by Apify during `apify push`, but you
   can run locally for verification):
   ```bash
   npm install
   ```
4. **Push the actor**:
   ```bash
   apify push
   ```
   This command uploads the current working directory to your Apify account, builds the Docker image
   using the included `Dockerfile`, and sets the default run configuration. After the command
   completes you will get a link to the actor in the Apify console.
5. **Set environment variables** (if needed): In the Apify console, open the actor, navigate to
   *Settings → Environment variables*, and add any of the variables described above.
6. **Run or schedule the actor**: Use the *Runs* tab in the console to start the actor manually or
   configure a schedule to keep the proxy online.

## Updating the actor

After you make additional changes, run `apify push` again. Apify will create a new build version and
update the default run configuration to the latest build unless you specify otherwise.

## Troubleshooting

- Ensure `yt-dlp` is available in the final Docker image. The included `Dockerfile` installs it
  through `pip` during the build step. If you change the Dockerfile, keep the dependency.
- For long video streams, increase `UPSTREAM_INACTIVITY_MS` to avoid premature aborts when the CDN
  has pauses in data delivery.
- Use the Apify *Run console* to view server logs for diagnostics.

