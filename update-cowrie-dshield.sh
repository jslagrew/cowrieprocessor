```bash
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
# Supports formatting such as:
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

                # Remove matching surrounding double quotes.
                if (value ~ /^".*"$/) {
                    value = substr(value, 2, length(value) - 2)
                }

                # Remove matching surrounding single quotes.
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

TMP_FILE="$(mktemp "${COWRIE_CFG}.tmp.XXXXXX")"
BACKUP_FILE="${COWRIE_CFG}.bak.$(date +%Y%m%d_%H%M%S)"

cleanup() {
    rm -f "$TMP_FILE"
}

trap cleanup EXIT

# Process both the [output_dshield] and [honeypot] sections.
set +e

awk \
    -v new_userid="$USERID_VALUE" \
    -v new_auth_key="$APIKEY_VALUE" '
    function finish_output_dshield() {
        if (!output_have_enabled) {
            print "enabled = true"
        }

        if (!output_have_userid) {
            print "userid = " new_userid
        }

        if (!output_have_auth_key) {
            print "auth_key = " new_auth_key
        }

        if (!output_have_batch_size) {
            print "batch_size = 100"
        }
    }

    function finish_honeypot() {
        if (!honeypot_have_auth_class) {
            print "auth_class = AuthRandom"
        }

        if (!honeypot_have_auth_parameters) {
            print "auth_class_parameters = 2, 5, 10"
        }
    }

    function finish_current_section() {
        if (in_output_dshield) {
            finish_output_dshield()
            in_output_dshield = 0
        }

        if (in_honeypot) {
            finish_honeypot()
            in_honeypot = 0
        }
    }

    # Detect section headers.
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        finish_current_section()

        if ($0 ~ /^[[:space:]]*\[output_dshield\][[:space:]]*$/) {
            in_output_dshield = 1
            found_output_dshield = 1

            output_have_enabled = 0
            output_have_userid = 0
            output_have_auth_key = 0
            output_have_batch_size = 0
        }

        if ($0 ~ /^[[:space:]]*\[honeypot\][[:space:]]*$/) {
            in_honeypot = 1
            found_honeypot = 1

            honeypot_have_auth_class = 0
            honeypot_have_auth_parameters = 0
        }

        print
        next
    }

    # Update [output_dshield].
    in_output_dshield &&
    /^[[:space:]]*enabled[[:space:]]*=/ {
        print "enabled = true"
        output_have_enabled = 1
        next
    }

    in_output_dshield &&
    /^[[:space:]]*userid[[:space:]]*=/ {
        print "userid = " new_userid
        output_have_userid = 1
        next
    }

    in_output_dshield &&
    /^[[:space:]]*auth_key[[:space:]]*=/ {
        print "auth_key = " new_auth_key
        output_have_auth_key = 1
        next
    }

    in_output_dshield &&
    /^[[:space:]]*batch_size[[:space:]]*=/ {
        print "batch_size = 100"
        output_have_batch_size = 1
        next
    }

    # Comment active settings in [honeypot].
    # Already-commented lines do not match and are preserved unchanged.
    in_honeypot &&
    /^[[:space:]]*data_path[[:space:]]*=/ {
        print "# " $0
        next
    }

    in_honeypot &&
    /^[[:space:]]*filesystem[[:space:]]*=/ {
        print "# " $0
        next
    }

    in_honeypot &&
    /^[[:space:]]*processes[[:space:]]*=/ {
        print "# " $0
        next
    }

    # Update authentication settings in [honeypot].
    in_honeypot &&
    /^[[:space:]]*auth_class[[:space:]]*=/ {
        print "auth_class = AuthRandom"
        honeypot_have_auth_class = 1
        next
    }

    in_honeypot &&
    /^[[:space:]]*auth_class_parameters[[:space:]]*=/ {
        print "auth_class_parameters = 2, 5, 10"
        honeypot_have_auth_parameters = 1
        next
    }

    {
        print
    }

    END {
        finish_current_section()

        if (!found_output_dshield) {
            exit 20
        }

        if (!found_honeypot) {
            exit 21
        }
    }
' "$COWRIE_CFG" > "$TMP_FILE"

AWK_STATUS=$?

set -e

if [[ $AWK_STATUS -eq 20 ]]; then
    echo "ERROR: [output_dshield] was not found in $COWRIE_CFG" >&2
    exit 1
elif [[ $AWK_STATUS -eq 21 ]]; then
    echo "ERROR: [honeypot] was not found in $COWRIE_CFG" >&2
    exit 1
elif [[ $AWK_STATUS -ne 0 ]]; then
    echo "ERROR: Failed to process $COWRIE_CFG" >&2
    exit "$AWK_STATUS"
fi

# Preserve the original permissions and ownership.
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
echo "Updated [output_dshield] settings:"
echo "  enabled = true"
echo "  userid = $USERID_VALUE"
echo "  auth_key = [REDACTED]"
echo "  batch_size = 100"
echo
echo "Updated [honeypot] settings:"
echo "  data_path: commented if present"
echo "  filesystem: commented if present"
echo "  processes: commented if present"
echo "  auth_class = AuthRandom"
echo "  auth_class_parameters = 2, 5, 10"
```
