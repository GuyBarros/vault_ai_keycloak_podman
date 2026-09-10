note: AI Companions have been used in the development of this demo.


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
CIBA approval: [localhost:8093](http://localhost:8093)  
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

On `feat/vault-ciba-stepup`, **create user** is an action with its own ACL policy `ciba-create-user`. In the Vault UI (Access control → ACL policies) set `ciba/create-user/admin` and `ciba/create-user/user` to `read` (CIBA) or `deny` (silent OBO) independently. List/search users are different actions and still use the session OBO. Open [localhost:8093](http://localhost:8093) to Approve. The audit trail is at [localhost:8092](http://localhost:8092).

### Level of Assurance (LoA)

Tokens now carry a `loa` claim reflecting how the human authenticated:

- **`loa: 1`** — plain password login, issued via the `token-exchange` client (used by the OBO/session flow).
- **`loa: 2`** — password **and** a valid TOTP code, issued via the `mfa-client` client for the `mfa-user` test account (password `mfa-user`, OTP secret `JBSWY3DPEHPK3PXP`). Keycloak's built-in Direct Grant flow refuses to issue a token from `mfa-client` at all unless a correct `totp` form field is supplied, since `mfa-user` has an OTP credential configured — the claim isn't self-reported, it's a consequence of what Keycloak actually verified.
- **`loa: 2`** — also on the token minted via `ciba-client` after a human approves a step-up request at [localhost:8093](http://localhost:8093). The CIBA-approved token is a *separate* token from the original session/OBO token — the session token you see client-side stays at `loa: 1` forever, since CIBA elevation happens server-side, purely for the Vault login on that one call. `user-mcp` logs the decoded `loa` on the `vault_ciba_approved` event so you can see it happen (e.g. `docker logs user-mcp | grep vault_ciba_approved`).

Run `make prove-loa` (stack must be up) to verify the password/MFA paths end to end, including the negative cases (no OTP, wrong OTP); `make prove-ciba-vault` now also asserts `loa: 2` on the CIBA-approved token. This is not yet wired into a Vault `bound_claims` gate on any `user-mcp` action — today it proves the IdP/claim layer only, the same layer as `CT-01.1`/`CT-01.2` in the security test catalog.
