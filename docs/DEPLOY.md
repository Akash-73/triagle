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
  --member="serviceAccount:$SA" --role="roles/storage.objectAdmin"
```

Then deploy with the bucket mounted at `/data`:

```bash
gcloud run deploy triagle --source . --region us-central1 \
  --execution-environment gen2 \
  --add-volume name=state,type=cloud-storage,bucket="$BUCKET" \
  --add-volume-mount volume=state,mount-path=/data \
  --min-instances 1 --max-instances 1 \
  --update-env-vars "TRIAGLE_STATE_FILE=/data/triagle-state.json.gz"
```

`--max-instances 1` matters: the queue lives in one process and one process
writes the file. `--min-instances 1` keeps that process warm so the first page
after a quiet spell is not slow.

The Connectors page says whether the queue is being saved and how many alerts
were restored at the last start.

## What is saved and what is not

Saved: every live alert still in the queue, the running totals, which tools
are sending, every approve, decline and lifted block, every report marked as
filed, and a customer's sector if an analyst changed it.

Not saved: the model's written account of a case (it is written again when the
case is opened) and the audit log file. On Cloud Run every audit entry also
goes to Cloud Logging, which keeps it.

The alert queue is written at most every 10 seconds
(`TRIAGLE_STATE_SECONDS`). A decision a person makes is written at once.
