#!/usr/bin/env bash

set -euo pipefail

COWRIE_CFG="/srv/cowrie/etc/cowrie.cfg"
DSHIELD_INI="/srv/dshield/etc/dshield.ini"
BACKUP_FILE="${COWRIE_CFG}.bak.$(date +%Y%m%d_%H%M%S)"
TMP_FILE="$(mktemp "${COWRIE_CFG}.tmp.XXXXXX")"

cleanup() {
    rm -f "$TMP_FILE"
}
trap cleanup EXIT

for file in "$COWRIE_CFG" "$DSHIELD_INI"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file not found: $file" >&2
        exit 1
    fi
done

get_ini_value() {
    local key="$1"

    awk -F '=' -v wanted="$key" '
        /^[[:space:]]*[#;]/ {
            next
        }

        {
            name = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)

            if (name == wanted) {
                value = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)

                if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
                    value = substr(value, 2, length(value) - 2)
                }

                print value
                exit
            }
        }
    ' "$DSHIELD_INI"
}

USERID_VALUE="$(get_ini_value userid)"
APIKEY_VALUE="$(get_ini_value apikey)"

if [[ -z "$USERID_VALUE" ]]; then
    echo "ERROR: userid is missing or empty in $DSHIELD_INI" >&2
    exit 1
fi

if [[ -z "$APIKEY_VALUE" ]]; then
    echo "ERROR: apikey is missing or empty in $DSHIELD_INI" >&2
    exit 1
fi

set +e

awk \
    -v userid="$USERID_VALUE" \
    -v authkey="$APIKEY_VALUE" '
    function finish_honeypot() {
        if (!found_auth_class) {
            print "auth_class = AuthRandom"
        }

        if (!found_auth_parameters) {
            print "auth_class_parameters = 2, 5, 10"
        }
    }

    function finish_dshield() {
        if (!found_enabled) {
            print "enabled = true"
        }

        if (!found_userid) {
            print "userid = " userid
        }

        if (!found_authkey) {
            print "auth_key = " authkey
        }

        if (!found_batch_size) {
            print "batch_size = 100"
        }
    }

    function finish_section() {
        if (section == "honeypot") {
            finish_honeypot()
        } else if (section == "output_dshield") {
            finish_dshield()
        }

        section = ""
    }

    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        finish_section()

        header = $0
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", header)

        if (header == "[honeypot]") {
            section = "honeypot"
            found_honeypot_section = 1
            found_auth_class = 0
            found_auth_parameters = 0
        } else if (header == "[output_dshield]") {
            section = "output_dshield"
            found_dshield_section = 1
            found_enabled = 0
            found_userid = 0
            found_authkey = 0
            found_batch_size = 0
        }

        print
        next
    }

    section == "honeypot" {
        line = $0
        normalized = line

        # Remove indentation, an optional comment marker and following spaces.
        sub(/^[[:space:]]*/, "", normalized)
        sub(/^#[[:space:]]*/, "", normalized)

        if (normalized ~ /^data_path[[:space:]]*=/) {
            sub(/^[[:space:]]*/, "", line)
            sub(/^#[[:space:]]*/, "", line)
            print "# " line
            next
        }

        if (normalized ~ /^filesystem[[:space:]]*=/) {
            sub(/^[[:space:]]*/, "", line)
            sub(/^#[[:space:]]*/, "", line)
            print "# " line
            next
        }

        if (normalized ~ /^processes[[:space:]]*=/) {
            sub(/^[[:space:]]*/, "", line)
            sub(/^#[[:space:]]*/, "", line)
            print "# " line
            next
        }

        if (normalized ~ /^auth_class_parameters[[:space:]]*=/) {
            if (!found_auth_parameters) {
                print "auth_class_parameters = 2, 5, 10"
                found_auth_parameters = 1
            }
            next
        }

        if (normalized ~ /^auth_class[[:space:]]*=/) {
            if (!found_auth_class) {
                print "auth_class = AuthRandom"
                found_auth_class = 1
            }
            next
        }
    }

    section == "output_dshield" {
        line = $0
        normalized = line

        sub(/^[[:space:]]*/, "", normalized)
        sub(/^#[[:space:]]*/, "", normalized)

        if (normalized ~ /^enabled[[:space:]]*=/) {
            if (!found_enabled) {
                print "enabled = true"
                found_enabled = 1
            }
            next
        }

        if (normalized ~ /^userid[[:space:]]*=/) {
            if (!found_userid) {
                print "userid = " userid
                found_userid = 1
            }
            next
        }

        if (normalized ~ /^auth_key[[:space:]]*=/) {
            if (!found_authkey) {
                print "auth_key = " authkey
                found_authkey = 1
            }
            next
        }

        if (normalized ~ /^batch_size[[:space:]]*=/) {
            if (!found_batch_size) {
                print "batch_size = 100"
                found_batch_size = 1
            }
            next
        }
    }

    {
        print
    }

    END {
        finish_section()

        if (!found_honeypot_section) {
            exit 20
        }

        if (!found_dshield_section) {
            exit 21
        }
    }
' "$COWRIE_CFG" > "$TMP_FILE"

AWK_STATUS=$?
set -e

case "$AWK_STATUS" in
    0)
        ;;
    20)
        echo "ERROR: [honeypot] stanza not found." >&2
        exit 1
        ;;
    21)
        echo "ERROR: [output_dshield] stanza not found." >&2
        exit 1
        ;;
    *)
        echo "ERROR: awk failed with status $AWK_STATUS." >&2
        exit "$AWK_STATUS"
        ;;
esac

chmod --reference="$COWRIE_CFG" "$TMP_FILE"
chown --reference="$COWRIE_CFG" "$TMP_FILE"

cp -a "$COWRIE_CFG" "$BACKUP_FILE"
mv "$TMP_FILE" "$COWRIE_CFG"

trap - EXIT

echo "Cowrie configuration updated."
echo "Backup: $BACKUP_FILE"
