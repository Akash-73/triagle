# Response actions: what is real and what is rehearsed

Triagle proposes a response for every alert it escalates: isolate a host,
disable an account, block an address. Each one goes to the tool that would
carry it out.

- A tool that is **connected** makes the change for real when a signed-in
  analyst approves it.
- A tool that is **not connected** is rehearsed. Triagle builds the exact API
  call, shows it on the action, writes it to the audit log and sends nothing.
  The action says "Rehearsal" so nobody mistakes it for a change.

Today one tool can be connected: the Google Cloud firewall.

## Block an address at the Google Cloud firewall

When an analyst approves "Block this address at the firewall", Triagle adds a
deny rule to the network's firewall for that one address (a /32). The rule is
named `triagle-block-<address>-in` (or `-out` for a destination), sits at
priority 900 and carries the approver's name in its description. "Lift the
block" deletes it. The Connectors page lists every block in force and can lift
one, which also works after a restart.

### Turn it on

1. Give Triagle's service account the role Compute Security Admin:

   ```bash
   PROJECT=$(gcloud config get-value project)
   SA=$(gcloud run services describe triagle --region us-central1 \
        --format='value(spec.template.spec.serviceAccountName)')
   gcloud projects add-iam-policy-binding "$PROJECT" \
     --member="serviceAccount:$SA" --role="roles/compute.securityAdmin" --condition=None
   ```

2. Name the customer whose machines are on this network, and the machines:

   | Setting | Meaning |
   |---|---|
   | `TRIAGLE_GCP_FIREWALL_CLIENT` | The customer. Unset means the connector is off. |
   | `TRIAGLE_GCP_FIREWALL_HOSTS` | Host names on this network, comma separated. Unset means all of that customer's. |
   | `TRIAGLE_GCP_FIREWALL_PROJECT` | Default: the project Triagle runs in. |
   | `TRIAGLE_GCP_FIREWALL_NETWORK` | Default `default`. |
   | `TRIAGLE_GCP_FIREWALL_TAGS` | Optional network tags; the rule then applies to those machines only. |
   | `TRIAGLE_GCP_FIREWALL_MAX` | Most blocks Triagle keeps at once. Default 40. |
   | `TRIAGLE_NEVER_BLOCK` | Addresses or ranges that must never be blocked. |

3. Sign-in must be on (`TRIAGLE_AUTH` not `off`). With sign-in off the
   firewall is left untouched.

4. In the console open Connectors, Response tools, and click "Check access and
   show blocks". It reads the firewall and reports whether Triagle may change
   it. Nothing is changed by the check.

### What it will not do

- Act for any other customer, or for a machine that is not on this network.
- Act without a signed-in analyst. The automatic tier, a rebuild of the queue
  and the "try an alert" box cannot reach the firewall.
- Block a private, reserved or documentation address, Google's browser-SSH and
  health-check ranges, anything in `TRIAGLE_NEVER_BLOCK`, or the address the
  approver is connecting from.
- Block a range. One address per rule.
- List or delete a rule it did not add.
- Keep more than the limit of blocks.

If Google Cloud refuses the call, nothing changes, the action stays open and
the reason is shown on it.

## Guest view

`TRIAGLE_GUEST=view` lets anyone with the address look around without signing
in: read every page, try an alert on the Connectors page and ask about a case.
A guest cannot approve, decline, lift, file a report, load a scenario or read
the audit log, and never sees the ingest key. It needs sign-in to be on.
