# Cloud deployment (multi-tenant server)

This deploys the **server** role (the shared, multi-tenant dashboard) as a
container on a single AWS instance, fronted by Caddy for automatic HTTPS, with
GitHub Actions building the image and triggering deploys via AWS SSM.

Agents stay **native** on each person's machine (see the main README) and sync
to this server with a per-agent token (issued on the server's `/machines` page).

```
GitHub push ─▶ Actions: build image ─▶ GHCR ─┐
                        └─ Actions: aws ssm send-command ─▶ EC2/Lightsail
                                                             ├─ Caddy (443, TLS)
                                                             └─ monitor (SQLite on a volume)
```

---

## 1. Provision the instance

- Ubuntu 22.04+ on Lightsail ($5–$10/mo) or a small EC2 (`t4g.small`).
- Install Docker + the compose plugin, and the SSM agent:
  ```bash
  curl -fsSL https://get.docker.com | sh
  sudo snap install amazon-ssm-agent --classic   # Ubuntu; preinstalled on Amazon Linux
  sudo systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service
  ```
- **Attach an IAM role to the instance** with the AWS-managed policy
  `AmazonSSMManagedInstanceCore` so Actions can run commands on it via SSM.
- Open ports **80** and **443** only (SSH optional; SSM removes the need for it).
- Point a DNS **A record** (e.g. `monitor.example.com`) at the instance IP.

## 2. Lay down the deploy files

On the instance:
```bash
sudo mkdir -p /opt/connection-monitor && cd /opt/connection-monitor
# copy deploy/docker-compose.yml and deploy/Caddyfile here
sudo cp /path/to/monitor.env.example monitor.env && sudo chmod 600 monitor.env
# edit monitor.env: set SECRET_KEY (python3 -c "import secrets;print(secrets.token_hex(32))")
#                   and SIGNUP_CODE (the invite code you share with friends)
echo "DOMAIN=monitor.example.com" | sudo tee .env
```
The GHCR image is public by default for this repo; if you make the package
private, run `docker login ghcr.io` on the instance with a read:packages PAT.

## 3. Create an IAM user for GitHub Actions

Least-privilege — it only needs to run the deploy command on your instance:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["ssm:SendCommand"],
      "Resource": [
        "arn:aws:ssm:*:*:document/AWS-RunShellScript",
        "arn:aws:ec2:*:*:instance/<YOUR_INSTANCE_ID>"
      ] },
    { "Effect": "Allow",
      "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      "Resource": "*" }
  ]
}
```
Create the user with **programmatic access** and save its access key ID + secret.
(Prefer GitHub OIDC + an assumed role once you're comfortable — it avoids
long-lived keys entirely. Static keys are fine to start.)

## 4. Save the credentials as GitHub repository secrets

In the repository: **Settings → Secrets and variables → Actions → New repository
secret**. Add these four (names must match `.github/workflows/deploy.yml`):

| Secret name | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | the IAM user's access key ID |
| `AWS_SECRET_ACCESS_KEY` | the IAM user's secret access key |
| `AWS_REGION` | e.g. `us-east-1` |
| `INSTANCE_ID` | the instance id, e.g. `i-0abc123…` |

Notes:
- Secrets are write-only in the UI and masked in logs; to change one, overwrite it.
- The `gh` CLI works too: `gh secret set AWS_ACCESS_KEY_ID` (paste when prompted).
- No secret is needed for the image push — Actions uses the built-in
  `GITHUB_TOKEN` to push to GHCR.
- App runtime secrets (`SECRET_KEY`, `SIGNUP_CODE`) live in `monitor.env` **on
  the instance**, not in GitHub.

## 5. First deploy

Push to `main` (or run the **Deploy** workflow manually). It builds the image,
pushes to GHCR, and SSM-runs `docker compose pull && up -d` on the instance.
Then browse to `https://monitor.example.com` — the **first account you register
becomes the admin**. Share the `SIGNUP_CODE` with friends so they can register,
and have each of them add their machine under **Machines** to get an agent token.

## 6. Point the agents at the server

On each friend's Mac (native install), add to `connection_monitor.env` and
restart the agent:
```
SERVER_URL=https://monitor.example.com
INGEST_API_KEY=<the token from the server's Machines page>
```

---

## Operations

- **Backups:** snapshot the instance volume (the SQLite DB is under the
  `monitor-data` Docker volume). Lightsail/EBS snapshots are the simplest route.
- **Logs:** `docker compose logs -f monitor` (and `caddy`) on the instance.
- **Rotate a leaked agent token:** revoke it on `/machines`; issue a new one.
- **Rotate AWS keys:** create a new IAM access key, update the two GitHub
  secrets, delete the old key.
- **Rollback:** deploys are tagged by commit SHA in GHCR; `docker compose` can
  be pinned to a specific `…:sha-<x>` tag to roll back.
