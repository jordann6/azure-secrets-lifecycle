#!/usr/bin/env bash
#
# Clears the evidence container so terraform destroy can complete.
#
# Evidence blobs sit under a time based immutability policy. The policy is
# created unlocked precisely so this is possible: a locked policy cannot
# be removed by anyone, including the subscription owner, and the storage
# account survives until every blob's retention window expires. That is
# correct for a real compliance programme and wrong for a project built to
# deploy, demo, and destroy in an afternoon.
#
# Versioning is on, so the versions have to go too.

set -euo pipefail

: "${EVIDENCE_STORAGE_ACCOUNT:?set EVIDENCE_STORAGE_ACCOUNT (run: eval "\$(make env)")}"
CONTAINER="${EVIDENCE_CONTAINER:-evidence}"

log() { printf '%s\n' "$*"; }

log "removing the immutability policy on ${EVIDENCE_STORAGE_ACCOUNT}/${CONTAINER}"
etag="$(az storage container immutability-policy show \
	--account-name "$EVIDENCE_STORAGE_ACCOUNT" \
	--container-name "$CONTAINER" \
	--query etag --output tsv 2>/dev/null || true)"

if [[ -n "$etag" && "$etag" != "None" ]]; then
	az storage container immutability-policy delete \
		--account-name "$EVIDENCE_STORAGE_ACCOUNT" \
		--container-name "$CONTAINER" \
		--if-match "$etag" --output none
	log "  policy removed"
else
	log "  no policy found, nothing to remove"
fi

log "deleting evidence blobs and their versions"
az storage blob delete-batch \
	--account-name "$EVIDENCE_STORAGE_ACCOUNT" \
	--source "$CONTAINER" \
	--delete-snapshots include \
	--auth-mode login --output none 2>/dev/null || true

log "evidence purge complete"
