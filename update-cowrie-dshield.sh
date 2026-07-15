#!/usr/bin/env bash

set -euo pipefail

COWRIE_CFG="/srv/cowrie/etc/cowrie.cfg"
DSHIELD_INI="/srv/dshield/etc/dshield.ini"

if [[ ! -f "$COWRIE_CFG" ]]; then
    echo "ERROR: Cowrie configuration not found: $COWRIE_CFG" >&2
    exit 1
fi

if [[ ! -f "$DSHIELD_INI" ]]; then
    echo "ERROR: DShield configuration not found: $DSHIELD_INI" >&2
    exit 1
fi

# Read a setting from dshield.ini.
# Matches lines such as:
# userid = 123456
# userid=123456
get_ini_value() {
    local key="$1"

    awk -F '=' -v wanted="$key" '
        /^[[:space:]]*[#;]/ {
            next
        }

        {
            name = $1
            gsub(/^[[:space:]]+/, "", name)
            gsub(/[[:space:]]+$/, "", name)

            if (name == wanted) {
                value = substr($0, index($0, "=") + 1)

                gsub(/^[[:space:]]+/, "", value)
                gsub(/[[:space:]]+$/, "", value)

                # Remove surrounding double quotes.
                if (value ~ /^".*"$/) {
                    value = substr(value, 2, length(value) - 2)
                }

                # Remove surrounding single quotes.
                if (value ~ /^\047.*\047$/) {
                    value = substr(value, 2, length(value) - 2)
                }

                print value
                exit
            }
        }
    ' "$DSHIELD_INI"
}

USERID_VALUE="$(get_ini_value "userid")"
APIKEY_VALUE="$(get_ini_value "apikey")"

if [[ -z "$USERID_VALUE" ]]; then
    echo "ERROR: userid was not found or is empty in $DSHIELD_INI" >&2
    exit 1
fi

if [[ -z "$APIKEY_VALUE" ]]; then
    echo "ERROR: apikey was not found or is empty in $DSHIELD_INI" >&2
    exit 1
fi

# Prevent values from interfering with awk replacement processing.
escape_awk_value() {
    printf '%s' "$1" | sed 's/\\/\\\\/g'
}

USERID_VALUE="$(escape_awk_value "$USERID_VALUE")"
APIKEY_VALUE="$(escape_awk_value "$APIKEY_VALUE")"

TMP_FILE="$(mktemp)"
BACKUP_FILE="${COWRIE_CFG}.bak.$(date +%Y%m%d_%H%M%S)"

cleanup() {
    rm -f "$TMP_FILE"
}

trap cleanup EXIT

awk \
    -v new_userid="$USERID_VALUE" \
    -v new_auth_key="$APIKEY_VALUE" '
    function add_missing_settings() {
        if (!have_enabled) {
            print "enabled = true"
        }

        if (!have_userid) {
            print "userid = " new_userid
        }

        if (!have_auth_key) {
            print "auth_key = " new_auth_key
        }

        if (!have_batch_size) {
            print "batch_size = 100"
        }
    }

    /^[[:space:]]*\[output_dshield\][[:space:]]*$/ {
        in_section = 1
        found_section = 1

        have_enabled = 0
        have_userid = 0
        have_auth_key = 0
        have_batch_size = 0

        print
        next
    }

    in_section && /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        add_missing_settings()
        in_section = 0
        print
        next
    }

    in_section && /^[[:space:]]*enabled[[:space:]]*=/ {
        print "enabled = true"
        have_enabled = 1
        next
    }

    in_section && /^[[:space:]]*userid[[:space:]]*=/ {
        print "userid = " new_userid
        have_userid = 1
        next
    }

    in_section && /^[[:space:]]*auth_key[[:space:]]*=/ {
        print "auth_key = " new_auth_key
        have_auth_key = 1
        next
    }

    in_section && /^[[:space:]]*batch_size[[:space:]]*=/ {
        print "batch_size = 100"
        have_batch_size = 1
        next
    }

    {
        print
    }

    END {
        if (in_section) {
            add_missing_settings()
        }

        if (!found_section) {
            exit 20
        }
    }
' "$COWRIE_CFG" > "$TMP_FILE"

AWK_STATUS=$?

if [[ $AWK_STATUS -eq 20 ]]; then
    echo "ERROR: [output_dshield] was not found in $COWRIE_CFG" >&2
    exit 1
elif [[ $AWK_STATUS -ne 0 ]]; then
    echo "ERROR: Failed to process $COWRIE_CFG" >&2
    exit "$AWK_STATUS"
fi

# Preserve original permissions and ownership.
chmod --reference="$COWRIE_CFG" "$TMP_FILE"
chown --reference="$COWRIE_CFG" "$TMP_FILE"

# Back up and replace the configuration.
cp -a "$COWRIE_CFG" "$BACKUP_FILE"
mv "$TMP_FILE" "$COWRIE_CFG"

trap - EXIT

echo "Cowrie configuration updated successfully."
echo "Configuration: $COWRIE_CFG"
echo "Backup:        $BACKUP_FILE"
echo
echo "[output_dshield] settings:"

awk '
    /^[[:space:]]*\[output_dshield\][[:space:]]*$/ {
        in_section = 1
        print
        next
    }

    in_section && /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        exit
    }

    in_section && /^[[:space:]]*enabled[[:space:]]*=/ {
        print
    }

    in_section && /^[[:space:]]*userid[[:space:]]*=/ {
        print
    }

    in_section && /^[[:space:]]*auth_key[[:space:]]*=/ {
        print "auth_key = [REDACTED]"
    }

    in_section && /^[[:space:]]*batch_size[[:space:]]*=/ {
        print
    }
' "$COWRIE_CFG"
