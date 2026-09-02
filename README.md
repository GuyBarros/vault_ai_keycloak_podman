## CPU architecture (ARM vs Intel)

The stack must run as **one** CPU architecture so Mac Apple Silicon, Intel Macs, and Windows/Linux PCs pull and build matching images. Set `DEMO_ARCH` in `docker-compose/setenv` (or on the `make` command line). If you leave it empty, `make` auto-detects from `uname -m`.

| Machine | `uname -m` | `DEMO_ARCH` | Docker platform | SPIRE binary |
|---|---|---|---|---|
| Apple Silicon (M1/M2/M3/M4) | `arm64` | `arm` | `linux/arm64` | `arm64` |
| ARM Linux server | `aarch64` | `arm` | `linux/arm64` | `arm64` |
| Intel/AMD PC or Intel Mac | `x86_64` | `intel` | `linux/amd64` | `x86_64` |

Aliases accepted: `arm64` / `aarch64` → arm; `amd64` / `x86_64` / `x64` → intel.

Do not mix arches in the same `docker compose` project. Switching `DEMO_ARCH` requires a full `make` (it already runs `docker compose down -v` and rebuilds).

### Choose the version

```bash
cd docker-compose/
cp setenv.example setenv   # first time only; fill WatsonX + client secrets
```

Edit `setenv`:

```bash
export DEMO_ARCH=arm      # Apple Silicon / ARM
# export DEMO_ARCH=intel  # Intel/AMD PC or Intel Mac
```

Or keep `DEMO_ARCH` empty in `setenv` and pass it only for that run:

```bash
. ./setenv
DEMO_ARCH=arm make          # native on Apple Silicon
DEMO_ARCH=intel make        # Intel/AMD, or emulation on Apple Silicon (slower)
```

Confirm what will be used:

```bash
. ./setenv
make help
```

### Commands

From `docker-compose/`, after `. ./setenv`:

```bash
. ./setenv
make              # down -v, build images for DEMO_ARCH, start the stack
make build        # build local images only (user-mcp, token-exchange, web, ai-agent)
make clear        # stop containers and delete volumes
make help         # print the resolved arch and the commands above
```

`make` writes `DOCKER_PLATFORM` and `SPIRE_ARCH` into the generated `.env` so Compose pins every service (including Vault, Keycloak, LiteLLM, and SPIRE) to that platform. SPIRE CLI/agent tarballs downloaded at boot follow `SPIRE_ARCH`.

## Build/Deploy

create a setenv file based on the example

```bash
cd docker-compose/
# setenv is hardcoded with ephemeral demo keys. It's safe.
. ./setenv
make
```

#### URLs
WebApp UI: [localhost:8080](http://localhost:8080)  
Keycloak: [localhost:8081](http://localhost:8081)  
LiteLLM: [localhost:4000/ui](http://localhost:4000/ui)  
Vault: [localhost:8200](http://localhost:8200)

Keycloak userpass admin/admin  
LiteLLM is SSO-enabled via Keycloak, userpass admin/admin  
Vault, check logs for token  

## Running the demo
#### Privileged user with write permissions
username: admin  
password: admin  
  
(00:50)
![Demo Admin gif](demo_admin.gif)

#### Read-only user
username: user  
password: user  
  
Login with email `user@demo.com` / password `user` if username `user` is rejected.

(00:30)
![Demo User gif](demo_user.gif)

OBS: This is a demo app to showcase Vault capabilities and was not extensively tested in terms of AI agent complex prompts. Plase use simple commands like *list*, *create*, *etc*. 
For **create_user** tool, only first name and email are enforced. If the model complains, be specific.
