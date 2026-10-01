# STREAM Innovation Club website

## Run locally

Requires Node.js 20 or newer. From this folder:

```powershell
npm start
```

Open <http://127.0.0.1:3000>. The `/healthz` endpoint reports whether the private inbox is configured.

## Set up the private inbox

Run `npm run setup-admin` once to create a random administrator password and a separate encryption key in the ignored `.env` file. Open that file locally to retrieve the password; never share or commit it. The encrypted application store is created under `.private-data/`, which is also ignored by Git. Set `APPLICATION_DATA_DIR` to a persistent volume path on hosted deployments. Back up `.env` and the application data directory together in a school-approved secure location: losing the encryption key makes stored applications unreadable.

Open <http://127.0.0.1:3000/admin> and sign in with username `admin` and the generated password. Admin sessions expire after four hours and are held in server memory; restart the server to end all sessions. Applications are rate-limited, validated, stored encrypted using AES-256-GCM, and can be marked reviewed from the private inbox.

## Deploy

Deploy this folder to a Node.js host that supports Node 20 or newer and runs `npm start`. Configure `PORT`, `HOST=0.0.0.0`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` (at least 16 characters), and `APPLICATION_DATA_KEY` (base64-encoded 32-byte key) in the host's secret/environment settings. The `setup-admin` command generates local credentials; do not copy a development `.env` to a public host. Use the hosting platform's persistent encrypted volume for `.private-data/`. Set `NODE_ENV=production`; enable TLS at the host. If TLS terminates at a trusted reverse proxy, explicitly set `TRUST_PROXY_TLS=true` so Secure admin-session cookies work.

The application inbox contains student personal data. Limit server and backup access to authorized school staff, use a school-approved host and retention period, and confirm required consent and data-protection practices before accepting real applications. This server stores applications encrypted at rest, but administrators can view their contents after signing in.
