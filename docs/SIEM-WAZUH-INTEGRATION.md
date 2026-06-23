# Wazuh (open-source SIEM) integration runbook

Goal: stand up Wazuh on a **separate droplet** and prove the platform's two
SIEM integration paths end-to-end:

- **Outbound push** — `POST /v1/siem/push/elastic` → ships ECS-shaped IOCs to the
  Wazuh **indexer** (`_bulk`). Code: [elasticBulk.ts](../apps/api/src/services/siemPush/elasticBulk.ts).
- **Inbound hunt** — `POST /v1/hunt` → NL→Cypher expands an indicator set, a
  read-only Lucene query is fired at the indexer (`_search`). Code:
  [siemSearch.ts](../apps/api/src/services/siemSearch.ts).

Wazuh's **indexer is an OpenSearch fork**, so it speaks the exact `_bulk` /
`_search` API the code already targets. The only code change needed was Basic
auth on the hunt side (OpenSearch uses `admin:password`, not Elastic API keys) —
shipped alongside this doc.

```
┌─────────────── API droplet (rinjani-api) ───────────────┐      ┌──────── Wazuh droplet ────────┐
│  v3-api                                                 │      │  wazuh.indexer  :9200 (OpenSearch)
│   ├─ push  POST /v1/siem/push/elastic ──ELASTIC_URL──┐  │ 9200 │  wazuh.manager  :1514/:1515/:55000
│   └─ hunt  POST /v1/hunt ───────────────SIEM_URL─────┼──┼─────▶│  wazuh.dashboard :443 (UI)
└──────────────────────────────────────────────────────┘  │      └───────────────────────────────┘
```

---

## 1. Provision the Wazuh droplet

- Size: **≥ 4 GB RAM / 2 vCPU** (the indexer is JVM-heavy), 50 GB disk. Ubuntu 22.04.
- Put it in the **same DigitalOcean VPC** as the API droplet so the indexer is
  reached over the private network — never expose `:9200` publicly.
- Kernel tunable the indexer requires:
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
  ```
- Install Docker + compose plugin (same as the API droplet).

## 2. Bring up Wazuh (single-node docker)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2
cd wazuh-docker/single-node

# Set a strong indexer admin password BEFORE first boot:
#   edit docker-compose.yml → services.wazuh.indexer + wazuh.manager env
#   INDEXER_PASSWORD, and config/wazuh_indexer/internal_users.yml hash.
# (Quickest: keep the default for the smoke test, rotate with the
#  wazuh-passwords-tool afterwards.)

docker compose -f generate-indexer-certs.yml run --rm generator   # self-signed certs
docker compose up -d
docker compose ps        # wait for wazuh.indexer / manager / dashboard = healthy (~2-3 min)
```

Dashboard: `https://<wazuh-droplet>` (default `admin` / the indexer password).

Sanity-check the indexer API locally on the droplet:
```bash
curl -sk -u admin:<INDEXER_PW> https://localhost:9200/_cluster/health?pretty
```

## 3. Lock down + grab the CA

- Firewall: allow `:9200` **only** from the API droplet's private IP.
  ```bash
  sudo ufw allow from <api-droplet-private-ip> to any port 9200 proto tcp
  ```
- Copy the indexer **root CA** to the API droplet (so Node trusts the self-signed
  cert instead of disabling TLS):
  ```bash
  # on the Wazuh droplet:
  docker cp single-node-wazuh.indexer-1:/usr/share/wazuh-indexer/certs/root-ca.pem ./wazuh-root-ca.pem
  scp wazuh-root-ca.pem <api-droplet>:~/rinjani-api/certs/wazuh-root-ca.pem
  ```

## 4. Wire the API droplet

Add to `~/rinjani-api/.env`:
```bash
# --- Outbound push (CTI IOCs → Wazuh indexer) ---
ELASTIC_URL=https://<wazuh-private-ip>:9200
ELASTIC_INDEX=rinjani-cti-iocs
ELASTIC_USER=admin
ELASTIC_PASSWORD=<INDEXER_PW>

# --- Inbound hunt (_search) ---
SIEM_URL=https://<wazuh-private-ip>:9200
SIEM_USER=admin
SIEM_PASSWORD=<INDEXER_PW>
# Self-contained round-trip: hunt the IOCs we push. Switch to wazuh-alerts-*
# once an agent is enrolled (step 7) to hunt real host telemetry.
SIEM_INDEX=rinjani-cti-iocs

# --- Trust the indexer's self-signed CA ---
NODE_EXTRA_CA_CERTS=/certs/wazuh-root-ca.pem
```

Mount the CA into the `v3-api` container — in the compose service add:
```yaml
    volumes:
      - ./certs/wazuh-root-ca.pem:/certs/wazuh-root-ca.pem:ro
```
Then recreate so the env + volume + mount take effect:
```bash
docker compose -p rinjani-api --profile apps up -d --force-recreate v3-api
```
> Quick smoke-test shortcut (NOT for keeping): instead of the CA, set
> `NODE_TLS_REJECT_UNAUTHORIZED=0` on `v3-api`. Disables TLS verification for all
> outbound calls — fine for a one-off check, replace with the CA mount after.

## 5. Verify the round-trip

```bash
KEY=<api-key>; API=https://api.rinjanianalytics.com
# (a) PUSH current IOCs → Wazuh indexer
curl -s -X POST "$API/v1/siem/push/elastic" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{}' | jq
#   → { ok: true, batchSize: N, indexed: N, errors: [] }

# (b) Confirm they landed (run on the Wazuh droplet)
curl -sk -u admin:<INDEXER_PW> "https://localhost:9200/rinjani-cti-iocs/_count?pretty"
#   → { count: N }

# (c) HUNT — fires _search at the indexer through the orchestrator
curl -s -X POST "$API/v1/hunt" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"question":"show recent malicious IPs"}' | jq
#   → a non-error response with siem.total ≥ 0 proves connectivity + auth + TLS.
```

`(a)` green + `(b)` count > 0 proves **push**. `(c)` returning without a `SIEM not
configured` / auth / TLS error proves **hunt**. That's the integration working.

## 6. Watch for trouble

- `SIEM 401` → wrong `SIEM_USER/PASSWORD` (must match the indexer admin).
- `unable to verify the first certificate` / `self-signed` → CA not mounted or
  `NODE_EXTRA_CA_CERTS` path wrong inside the container.
- `ECONNREFUSED` / timeout → `:9200` not reachable from the API droplet (VPC IP?
  firewall rule?).
- Push `errors: [...]` but `ok:false` → index mapping conflict; the default
  `rinjani-cti-iocs` index is created on first write, so this usually means auth.

## 7. (Optional) Real telemetry to hunt

For the hunt to return real host events rather than our own pushed IOCs, enroll
an agent and point `SIEM_INDEX=wazuh-alerts-*`:
```bash
# on any host to monitor (can be the API droplet):
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb
sudo WAZUH_MANAGER='<wazuh-private-ip>' dpkg -i ./wazuh-agent_4.9.2-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```
Alerts will populate `wazuh-alerts-*`; switch `SIEM_INDEX` and re-run the hunt.
