# Langfuse Integration with OpenClaw

This sample deploys a self-hosted Langfuse instance and connects it to an
existing OpenClaw gateway through the Langfuse bridge plugin.

The script:

1. Generates Langfuse service secrets, an administrator account, and a project
   API key pair.
2. Deploys Langfuse with Docker Compose.
3. Clones and installs `openclaw-x-langfuse-plugin`.
4. Adds the plugin to OpenClaw without removing existing allowed plugins,
   validates the configuration, and restarts the gateway.

## Prerequisites

- Linux with Git, OpenSSL, Node.js, and npm
- Docker Engine with Docker Compose v2
- OpenClaw 2026.6.1 or later, with its gateway installed as a service
- Permission to run Docker as the current user

## Deploy

The defaults use `$HOME/langfuse` and `$HOME/openclaw-x-langfuse-plugin`, which
also permits reuse of existing clones.

```bash
cd samples/ai/langfuse-openclaw
chmod +x deploy.sh
./deploy.sh
```

To override settings, export values before running the script. See
`deploy.env.example` for all supported settings.

```bash
export LANGFUSE_BASE_URL=http://192.0.2.10:3000
export LANGFUSE_ADMIN_EMAIL=admin@example.com
./deploy.sh
```

The generated secrets are stored in `$HOME/langfuse/.env` with mode `600` and
are reused on subsequent runs. Do not commit or share this file. Set
`LANGFUSE_ENV_FILE` to use a different location. If a running Langfuse stack has
no environment file, the script preserves its credentials from the container
configuration and reuses the project keys from an existing OpenClaw Langfuse
plugin entry. It stops without changing the stack if those keys are unavailable.

## Verify

```bash
docker compose --project-directory "$HOME/langfuse" \
   --env-file "$HOME/langfuse/.env" \
   --file "$HOME/langfuse/docker-compose.yml" ps
openclaw config validate
openclaw plugins list
openclaw gateway status
```

Open the configured Langfuse URL and sign in with
`LANGFUSE_INIT_USER_EMAIL`/`LANGFUSE_INIT_USER_PASSWORD` from the generated
`.env` file. Send a message through an OpenClaw channel or its web interface,
then confirm that the trace appears in the `OpenClaw` Langfuse project.

Direct `openclaw agent` CLI runs do not emit the diagnostic events consumed by
the plugin.