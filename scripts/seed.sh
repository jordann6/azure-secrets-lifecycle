#!/usr/bin/env bash
#
# Builds and tears down the demo secret estate.
#
# Runs as the operator through the az CLI, never as the platform's managed
# identity. That split is the point: the platform identity holds
# Key Vault Reader and could not create any of this even if the code
# asked it to.
#
# On ages: Azure will not let a creation date be backdated any more than
# AWS will, so every seeded object carries a secops:simulated-age-days
# tag. The scanner honours it and flags the record age_simulated, and the
# dashboard says so wherever the number appears. Demo data that quietly
# passes for production telemetry is worse than no demo data.
#
# Usage:
#   scripts/seed.sh create    create the estate
#   scripts/seed.sh destroy   remove everything this script created
#
# Requires KEY_VAULT_NAME and APP_CONFIG_NAME in the environment; run
# `eval "$(make env)"` first.

set -euo pipefail

PREFIX="secops-test"
TAG="secops:simulated-age-days"

: "${KEY_VAULT_NAME:?set KEY_VAULT_NAME (run: eval "\$(make env)")}"
: "${APP_CONFIG_NAME:?set APP_CONFIG_NAME (run: eval "\$(make env)")}"

# name|simulated age days|expiry set
SECRETS=(
	"db-primary|400|no"
	"db-replica|200|no"
	"api-key-stripe|500|no"
	"api-key-datadog|90|yes"
	"app-jwt-signing|120|yes"
	"svc-queue-token|60|yes"
	"legacy-ftp|700|no"
	"redis-auth|150|no"
	"smtp-creds|365|no"
	"webhook-hmac|45|yes"
)

# name|simulated age days|auto renew
CERTIFICATES=(
	"tls-edge|280|yes"
	"tls-internal|410|no"
	"client-mtls|95|no"
)

# key|simulated age days|key vault reference
APP_CONFIG_KEYS=(
	"app/db-conn|300|no"
	"app/feature-key|30|no"
	"batch/export-token|250|no"
	"orphan/old-license|600|no"
	"orphan/deprecated-key|420|yes"
)

ENTRA_APP="${PREFIX}-legacy-integration"

log() { printf '%s\n' "$*"; }

# Deliberately not a plausible looking credential. Anyone who finds one of
# these in a log should be able to tell at a glance that it is inert.
placeholder() {
	printf 'not-a-real-secret-%s' "$(printf '%s' "$1" | shasum -a 256 | cut -c1-12)"
}

create_secrets() {
	log "creating ${#SECRETS[@]} Key Vault secrets in ${KEY_VAULT_NAME}"
	local entry name age expiry args
	for entry in "${SECRETS[@]}"; do
		IFS='|' read -r name age expiry <<<"$entry"
		args=(--vault-name "$KEY_VAULT_NAME" --name "${PREFIX}-${name}"
			--value "$(placeholder "${PREFIX}-${name}")"
			--tags "${TAG}=${age}" "owner=platform-team" "seeded-by=secops")
		# Only some seeded secrets get an expiry, so the scan reports both
		# a CIS 8.3 pass set and a real failure set rather than all of one.
		if [[ "$expiry" == "yes" ]]; then
			args+=(--expires "$(date -u -v+180d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null ||
				date -u -d '+180 days' '+%Y-%m-%dT%H:%M:%SZ')")
		fi
		az keyvault secret set "${args[@]}" --output none
		log "  ${PREFIX}-${name} (age ${age}d, expiry ${expiry})"
	done
}

create_certificates() {
	log "creating ${#CERTIFICATES[@]} Key Vault certificates"
	local entry name age renew policy
	for entry in "${CERTIFICATES[@]}"; do
		IFS='|' read -r name age renew <<<"$entry"
		policy="$(mktemp)"
		cert_policy "$name" "$renew" >"$policy"
		az keyvault certificate create --vault-name "$KEY_VAULT_NAME" \
			--name "${PREFIX}-${name}" --policy "@${policy}" --output none
		az keyvault certificate set-attributes --vault-name "$KEY_VAULT_NAME" \
			--name "${PREFIX}-${name}" \
			--tags "${TAG}=${age}" "owner=platform-team" "seeded-by=secops" --output none
		rm -f "$policy"
		log "  ${PREFIX}-${name} (age ${age}d, auto renew ${renew})"
	done
}

# An AutoRenew lifetime action is the one true rotation engine Key Vault
# has, so at least one seeded certificate carries it. It is what makes the
# "verified rotation path" metric non zero.
cert_policy() {
	local name="$1" renew="$2" lifetime=""
	if [[ "$renew" == "yes" ]]; then
		lifetime=',"lifetimeActions":[{"action":{"actionType":"AutoRenew"},"trigger":{"daysBeforeExpiry":30}}]'
	fi
	cat <<-JSON
		{"issuerParameters":{"name":"Self"},
		 "keyProperties":{"exportable":true,"keySize":2048,"keyType":"RSA","reuseKey":false},
		 "secretProperties":{"contentType":"application/x-pkcs12"},
		 "x509CertificateProperties":{"subject":"CN=${name}.secops.invalid","validityInMonths":12}
		 ${lifetime}}
	JSON
}

create_app_config() {
	log "creating ${#APP_CONFIG_KEYS[@]} App Configuration key values"
	local entry key age kvref
	for entry in "${APP_CONFIG_KEYS[@]}"; do
		IFS='|' read -r key age kvref <<<"$entry"
		if [[ "$kvref" == "yes" ]]; then
			# A Key Vault reference holds no material of its own: its
			# lifecycle is delegated to the referenced secret, which this
			# same scan already covers. The scanner scores it that way
			# rather than counting one risk against two resources.
			az appconfig kv set-keyvault --name "$APP_CONFIG_NAME" \
				--key "${PREFIX}/${key}" \
				--secret-identifier "https://${KEY_VAULT_NAME}.vault.azure.net/secrets/${PREFIX}-legacy-ftp" \
				--tags "${TAG}=${age}" "seeded-by=secops" --yes --output none
		else
			az appconfig kv set --name "$APP_CONFIG_NAME" \
				--key "${PREFIX}/${key}" \
				--value "$(placeholder "${PREFIX}/${key}")" \
				--tags "${TAG}=${age}" "seeded-by=secops" --yes --output none
		fi
		log "  ${PREFIX}/${key} (age ${age}d, key vault reference ${kvref})"
	done
}

# The Entra sweep needs something to find. This is the one place the seed
# creates a real static credential, which is exactly the anti pattern the
# platform reports on. The generated password is discarded immediately;
# nothing here needs to authenticate with it.
create_entra_app() {
	log "creating Entra app registration ${ENTRA_APP}"
	local app_id
	if ! app_id="$(az ad app create --display-name "$ENTRA_APP" \
		--query appId --output tsv 2>/dev/null)"; then
		log "  skipped: the signed in identity cannot create app registrations."
		log "  Application Developer or Application.ReadWrite.All is required."
		log "  The Key Vault and App Configuration sweeps are unaffected."
		return 0
	fi

	az ad app credential reset --id "$app_id" --display-name legacy-sync \
		--years 2 --output none >/dev/null 2>&1 || true
	log "  ${app_id} with a two year static credential, which the scan will flag"
}

destroy_entra_app() {
	local app_id
	app_id="$(az ad app list --display-name "$ENTRA_APP" \
		--query "[0].appId" --output tsv 2>/dev/null || true)"
	[[ -z "$app_id" || "$app_id" == "None" ]] && return 0

	log "deleting Entra app registration ${app_id}"
	az ad app delete --id "$app_id" --output none 2>/dev/null || true
}

create() {
	create_secrets
	create_certificates
	create_app_config
	create_entra_app
	log ""
	log "seed complete. next: make traffic, wait 5 to 15 minutes for audit"
	log "events to reach Log Analytics, then make scan."
}

destroy() {
	local entry name key

	log "removing Key Vault secrets and certificates"
	for entry in "${SECRETS[@]}"; do
		IFS='|' read -r name _ _ <<<"$entry"
		az keyvault secret delete --vault-name "$KEY_VAULT_NAME" \
			--name "${PREFIX}-${name}" --output none 2>/dev/null || true
	done
	for entry in "${CERTIFICATES[@]}"; do
		IFS='|' read -r name _ _ <<<"$entry"
		az keyvault certificate delete --vault-name "$KEY_VAULT_NAME" \
			--name "${PREFIX}-${name}" --output none 2>/dev/null || true
	done

	# Purge protection is on for this vault, so purge is expected to fail.
	# It is attempted anyway because a vault without it leaves tombstones
	# that collide with the next seed.
	log "purging soft deleted objects where the vault allows it"
	for entry in "${SECRETS[@]}"; do
		IFS='|' read -r name _ _ <<<"$entry"
		az keyvault secret purge --vault-name "$KEY_VAULT_NAME" \
			--name "${PREFIX}-${name}" --output none 2>/dev/null || true
	done

	log "removing App Configuration key values"
	for entry in "${APP_CONFIG_KEYS[@]}"; do
		IFS='|' read -r key _ _ <<<"$entry"
		az appconfig kv delete --name "$APP_CONFIG_NAME" \
			--key "${PREFIX}/${key}" --yes --output none 2>/dev/null || true
	done

	destroy_entra_app
	log "seed destroy complete"
}

case "${1:-create}" in
create) create ;;
destroy) destroy ;;
*)
	echo "usage: $0 [create|destroy]" >&2
	exit 2
	;;
esac
