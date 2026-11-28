# Running Triagle on Cloud Run

One service, one instance. Everything below is set with flags on
`gcloud run deploy`; nothing is edited by hand afterwards.

## What to set

| Setting | What it does |
|---|---|
| `TRIAGLE_INGEST_KEY` | The key a tool sends with its alerts. Without it nothing can be sent in. |
| `TRIAGLE_AUTH=on` | Sign-in. Needed for any real change (see RESPONSE.md). |
| `TRIAGLE_ADMIN_PASSWORD` | Password of the `admin` analyst account. |
| `TRIAGLE_SECRET` | Signs sessions. Set it, or everyone is signed out at each restart. |
| `TRIAGLE_GUEST=view` | Anyone with the address can look around without signing in. Changes still need a sign-in. |
| `TRIAGLE_STATE_FILE` | Where the queue, decisions and filed reports are saved, so a restart does not empty the console. |
| `TRIAGLE_GCP_FIREWALL_CLIENT`, `TRIAGLE_GCP_FIREWALL_HOSTS` | Makes "Block this address" a real firewall rule for that customer's machines. |
| `TRIAGLE_WAZUH_URL` | Address of the Wazuh dashboard. Each Wazuh alert then has an "Open in Wazuh" button (see WAZUH.md). |
| `TRIAGLE_DEMO=true` | Lets a signed-in analyst send a test stream from the Live page. |
| `TRIAGLE_DEMO_SCENARIOS` | Which built-in customers the test stream offers, for example `bank`. Unset means all. |
| `TRIAGLE_THINKING` | How long the model may think before writing: `minimal`, `low` (default), `medium`, `high`, or `default` to leave the model's own setting. |

## The model on every alert

Off unless you switch it on. With it on, the model reads every closure Triagle
makes on its own and investigates every alert that goes to a person, without
waiting for anyone to open it. It can send an alert to a person and can never
close one.

| Setting | What it does |
|---|---|
| `TRIAGLE_ARRIVAL=on` | Switches the work on. |
| `TRIAGLE_ARRIVAL_DAILY_USD` | What this work may spend in a day, India time. Default `1.00`. At the limit it stops until midnight. |
| `TRIAGLE_WORK_KEY` | A key for `/api/work`, at least 16 characters. The intake key works too; a key of its own means the scheduler does not hold the key that can send alerts in. |
| `TRIAGLE_ARRIVAL_BATCH` | Closures read in one call. Default `10`. |
| `TRIAGLE_ARRIVAL_THINKING` | How long the model thinks on a batch of closures: `minimal`, `low` (default), `medium`, `high`. |
| `TRIAGLE_ARRIVAL_SECONDS` | How long one call to `/api/work` keeps starting new pieces of work. Default `45`. |

Cloud Run gives a service CPU only while it answers a request, so the work is
done inside a request: a Cloud Scheduler job calls `/api/work` every minute.
One call works for up to 45 seconds and a second call that arrives meanwhile
is told the work is already going on.

One script sets it up. Run it in Cloud Shell, from the repository, after the
deploy:

```bash
bash scripts/arrival_cloud.sh                 # switch it on, with the limit that is set, else $1 a day
DAILY_USD=3 bash scripts/arrival_cloud.sh     # the same, with a different limit for the day
bash scripts/arrival_cloud.sh status          # what the service says about the work. Changes nothing
bash scripts/arrival_cloud.sh off             # stop the work. What was read and investigated stays
```

It makes a key for the work and keeps it in Secret Manager, sets the three
settings on the service as one new revision, makes the scheduler job, and
then asks the service to work once and prints what it answered. Each step is
safe to run again, and the key is never printed. By hand it is:

```bash
gcloud run services update triagle --region us-central1 \
  --update-env-vars "TRIAGLE_ARRIVAL=on,TRIAGLE_ARRIVAL_DAILY_USD=1.00" \
  --update-secrets "TRIAGLE_WORK_KEY=triagle-work-key:latest"
gcloud scheduler jobs create http triagle-work --location us-central1 \
  --schedule "* * * * *" --uri "$URL/api/work" --http-method POST \
  --headers "X-Triagle-Key=$WORK_KEY" --attempt-deadline 180s
```

What it costs is on the Overview, counted by job from the token counts the
API reports. As a guide, a batch of ten closures is one short call and an
investigation is four to six calls. The first day is the most expensive,
because every alert already in the queue is read once.

On a host that does not throttle (a VM, a laptop) no scheduler is needed:
`TRIAGLE_ARRIVAL_THREAD=on` does the same work from a thread every
`TRIAGLE_ARRIVAL_EVERY` seconds (default 30). Set `TRIAGLE_PUBLIC_URL` there,
so that what the work writes back to the SIEM carries a link that opens.

## Saved state on a bucket

Cloud Run's own disk is wiped at every restart, so the state file goes on a
Cloud Storage bucket mounted into the service.

```bash
PROJECT=$(gcloud config get-value project)
BUCKET="triagle-state-$PROJECT"
SA=$(gcloud run services describe triagle --region us-central1 \
     --format='value(spec.template.spec.serviceAccountName)')

gcloud storage buckets create "gs://$BUCKET" --location=us-central1 --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$SA" --role="roles/storage.objectUser"
```

Then deploy with the bucket mounted at `/data`:

```bash
gcloud run deploy triagle --source . --region us-central1 \
  --execution-environment gen2 \
  --add-volume name=state,type=cloud-storage,bucket="$BUCKET" \
  --add-volume-mount volume=state,mount-path=/data \
  --min-instances 1 --max-instances 1 --memory 1Gi \
  --update-env-vars "TRIAGLE_STATE_FILE=/data/triagle-state.json.gz"
```

A mounted bucket needs the second-generation environment, which Cloud Run
picks on its own when a volume is present; the flag just makes it explicit.
Each save is an upload that is staged in memory, hence the 1 GiB.

`--max-instances 1` matters: the queue lives in one process and one process
writes the file. `--min-instances 1` keeps that process warm so the first page
after a quiet spell is not slow.

The Connectors page says whether the queue is being saved and how many alerts
were restored at the last start.

For an uptime check use `/health`. Cloud Run answers `/healthz` itself and
never passes it to the service.

## What is saved and what is not

Saved: every live alert still in the queue, the running totals, which tools
are sending, every approve, decline and lifted block, every report marked as
filed, and a customer's sector if an analyst changed it.

Also saved: the model's readings and second opinions, the accounts it wrote
ahead for alerts that need a person, and the record of what that work cost.

Not saved: the model's written account of a case (it is written again when the
case is opened) and the audit log file. On Cloud Run every audit entry also
goes to Cloud Logging, which keeps it.

The alert queue is written at most every 10 seconds
(`TRIAGLE_STATE_SECONDS`). A decision a person makes is written at once.

## Hardening a deployment

Before any deploy, take a copy of the saved state. This is safe on any version:

```bash
bash scripts/harden_cloud.sh backup
```

Then deploy version 0.9 or later, and in Cloud Shell, from the repository:

```bash
bash scripts/harden_cloud.sh
```

It does five things, and each is safe to run again.

1. **Backups.** A dated copy of the saved state is taken first. From then on
   the bucket keeps every earlier version of the file for 7 days, and refuses
   public access. The copy is in the same bucket, so it protects against a
   bad save or a bad deploy, not against losing the bucket.
2. **Secrets.** The sign-in password, the signing secret and the intake key
   move from the service's plain settings into Secret Manager. Nothing secret
   is printed.
3. **A key for each customer.** The existing intake key is tied to one
   customer (`CUSTOMER="Name" bash scripts/harden_cloud.sh` to say which; it
   must be the name the forwarder already sends). From then on the key decides
   whose alerts arrive, whatever name the sender writes. Add a customer by
   adding a line `Customer name=key` to the secret `triagle-ingest-keys`.
4. **Not root.** The bucket is mounted for uid 10001. At its next start the
   app finds it can write there as an unprivileged user and gives up root.
   Until then it stays root and says so in its log, because running
   unprivileged over a root-owned mount would silently stop every save.
5. **A check, and a way back.** The script tries the intake key before it
   changes anything and again on the new revision. If the key no longer gets
   in, it puts the previous revision back by itself and says so. If the new
   revision does not start at all, Cloud Run keeps serving the old one.

Afterwards open `/health` while signed in. It reports `runs_as`,
`customer_keys`, `single_sign_on`, `second_factor` and `saved_state`.

### Sign-in for a team

| Setting | What it does |
|---|---|
| `TRIAGLE_USERS` | Named accounts: `name:role:hash` or `name:role:hash:KEY`. `python -m app.auth hash` makes the hash, `python -m app.auth totp name` makes the authenticator key |
| `TRIAGLE_ADMIN_TOTP` | An authenticator key for `admin`. With it set, `admin` cannot sign in without the current six-digit code |
| `TRIAGLE_OIDC_CLIENT_ID`, `TRIAGLE_OIDC_CLIENT_SECRET` | Single sign-on. From your identity provider's console. The redirect address to register is `https://YOUR-ADDRESS/auth/callback` |
| `TRIAGLE_OIDC_ISSUER` | Default `https://accounts.google.com`. Any OpenID Connect provider works, for example a Microsoft Entra ID tenant |
| `TRIAGLE_OIDC_USERS` | Who may come in, and as what: `email:analyst,email:viewer`. Nobody else gets in, whatever account they hold at the provider |
| `TRIAGLE_PASSWORD_LOGIN=off` | One way in: turns password sign-in off. Ignored unless single sign-on is fully set up |
| `TRIAGLE_PUBLIC_URL` | The console's own address, when it sits behind a custom domain |
| `TRIAGLE_FORWARDED_HOPS` | How many proxies of yours stand in front. 1 on Cloud Run (the default there), 2 behind a load balancer |
| `TRIAGLE_CONTACT` | An address shown on the public `/security` page |

### What the build checks

`docker build` runs every test, so `gcloud run deploy --source .` cannot
publish a change that breaks one. GitHub builds the same image on every push
and confirms it starts, answers, and does not run as root.
