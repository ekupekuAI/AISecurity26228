# Deploying TrustVision for shared testing

TrustVision is **not** a serverless app — it runs a Node gateway and a Python ML engine as
one long-running container with a persistent evidence database. It cannot run on Vercel,
Netlify, or any serverless host. To share it with a team you need a small **VM** (a normal
Linux computer in the cloud) or an always-on machine, plus Docker.

> This is a **shared-test / demo** posture. The production target is a private, air-gapped
> node with no public ingress. Hosting it publicly is fine for team testing — just know it
> is no longer air-gapped.

Everything below assumes you have Docker installed on the host.

---

## What you provide (only you can do these)
- A **VM**: DigitalOcean droplet, AWS EC2, Azure/GCP VM, Hetzner — 2 vCPU / 4–8 GB RAM, ~$6–12/mo. Model analysis (torch) is memory-hungry.
- A **domain** (or subdomain), e.g. `assurance.yourteam.com`.
- A **DNS A-record** pointing that domain at the VM's public IP.

I can't create the cloud account, buy the domain, or enter your credentials — those are yours. I can walk you through every command.

---

## Path A — VM + your domain (persistent HTTPS link) ✅ recommended for a team

On the VM, after DNS points your domain at it:

```bash
git clone https://github.com/ekupekuAI/AISecurity26228.git
cd AISecurity26228
cp deploy/.env.example .env
# edit .env: set AUTH_SECRET, AIA_BOOTSTRAP_PASSWORD, PUBLIC_DOMAIN, APP_URL
cd deploy
docker compose -f docker-compose.yml -f docker-compose.public.yml --env-file ../.env up -d --build
```

Caddy issues a Let's Encrypt certificate for your domain automatically. In ~1 minute the app is live at `https://your-domain`. Share that link with your team.

First login: the admin is whatever you set in `.env` (`AIA_BOOTSTRAP_USER` / `AIA_BOOTSTRAP_PASSWORD`). If you left the password blank, read the one-time password from the logs:
```bash
docker compose logs | grep -i bootstrap
```

Open ports on the VM firewall: **80 and 443** only.

---

## Path B — Cloudflare Tunnel (free, no open ports, needs a Cloudflare domain)

Run the app privately and expose it through Cloudflare (works from a VM or an always-on machine). No inbound ports, no VM firewall changes.

```bash
cd deploy && docker compose --env-file ../.env up -d --build   # app on 127.0.0.1:3000
cloudflared tunnel login
cloudflared tunnel --url http://localhost:3000                  # or bind a named tunnel to your domain
```

For a stable custom domain, create a *named* tunnel and a CNAME in Cloudflare (their docs walk you through it). Set `APP_URL=https://your-tunnel-domain` in `.env` first so the session cookie works.

---

## Path C — quick throwaway link (fastest, minutes, no VM, no domain)

Just to let a teammate click it once, from any machine running the app:

```bash
cloudflared tunnel --url http://localhost:3000
```
You get a temporary `https://random-name.trycloudflare.com` link. It dies when you stop the command. Good for a 10-minute demo, not for ongoing testing.

---

## Test it locally first (free, no hosting)
```bash
npm run ml      # Python engine on :8000
npm run dev     # gateway + UI on http://localhost:3000
```

## Operate
```bash
docker compose ... logs -f          # watch
docker compose ... down             # stop (evidence volume persists)
docker compose ... pull && ... up -d --build   # update to a new build
```
The audit ledger, signing keys, and analyses live in the `assurance-data` volume and survive restarts and updates. Back it up before destroying the VM.

## Provision the feature backbone (optional, improves dataset analytics)
On a connected machine, run `python ml-engine/scripts/provision_backbone.py` to stage
`ml-engine/assets/backbone_resnet18.pt`, then rebuild. Without it, embedding-based checks run
degraded and say so — nothing breaks.
