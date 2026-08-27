# Langfuse Integration with OpenClaw

This sample deploys a self-hosted Langfuse instance and connects it to an
existing OpenClaw gateway through the Langfuse bridge plugin.

The script:

1. Downloads only the Langfuse Docker Compose file into this sample directory.
2. Generates Langfuse service secrets, an administrator account, and a project
   API key pair.
3. Deploys Langfuse with Docker Compose.
4. Clones and installs `openclaw-x-langfuse-plugin`.
5. Adds the plugin to OpenClaw without removing existing allowed plugins,
   validates the configuration, and restarts the gateway.

## Prerequisites

- Linux with curl, Git, OpenSSL, Node.js, and npm
- Docker Engine with Docker Compose v2
- OpenClaw 2026.6.1 or later, with its gateway installed as a service
- Permission to run Docker as the current user

## Deploy

By default, Langfuse's Compose file and generated `.env` are stored in the
`langfuse` directory beside `deploy.sh`. The plugin clone remains at
`openclaw-x-langfuse-plugin` beside `deploy.sh` and is reused on subsequent
runs.

```bash
cd tests/test-agent/langfuse-openclaw
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

The generated secrets are stored in `./langfuse/.env` with mode `600` and are
reused on subsequent runs. The local `langfuse` directory is ignored by Git; do
not share its `.env` file. Set `LANGFUSE_DIR` or `LANGFUSE_ENV_FILE` to use a
different location, and `LANGFUSE_COMPOSE_URL` to download from a pinned tag or
another source. If a running Langfuse stack has no environment file, the script
preserves its credentials from the container configuration and reuses the
project keys from an existing OpenClaw Langfuse plugin entry. It stops without
changing the stack if those keys are unavailable.

## Verify

```bash
docker compose --project-directory "./langfuse" \
   --env-file "./langfuse/.env" \
   --file "./langfuse/docker-compose.yml" ps
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