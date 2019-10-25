set -e

#=======================================
# Functions
#=======================================

RESTORE='\033[0m'
RED='\033[00;31m'
YELLOW='\033[00;33m'
BLUE='\033[00;34m'
GREEN='\033[00;32m'

function color_echo {
    color=$1
    msg=$2
    echo -e "${color}${msg}${RESTORE}"
}

function echo_fail {
    msg=$1
    echo
    color_echo "${RED}" "${msg}"
    exit 1
}

function echo_warn {
    msg=$1
    color_echo "${YELLOW}" "${msg}"
}

function echo_info {
    msg=$1
    echo
    color_echo "${BLUE}" "${msg}"
}

function echo_details {
    msg=$1
    echo "  ${msg}"
}

function echo_done {
    msg=$1
    color_echo "${GREEN}" "  ${msg}"
}

function validate_required_input {
    key=$1
    value=$2
    if [ -z "${value}" ] ; then
        echo_fail "[!] Missing required input: ${key}"
    fi
}

function validate_required_input_with_options {
    key=$1
    value=$2
    options=$3

    validate_required_input "${key}" "${value}"

    found="0"
    for option in "${options[@]}" ; do
        if [ "${option}" == "${value}" ] ; then
            found="1"
        fi
    done

    if [ "${found}" == "0" ] ; then
        echo_fail "Invalid input: (${key}) value: (${value}), valid options: ($( IFS=$", "; echo "${options[*]}" ))"
    fi
}

function parse_list {
    if [ -z "$2" ]; then
        echo_fail "Failed to split list $1"
    fi
    local -n RESULT_ARRAY=$3
    IFS='|' read -a RESULT_ARRAY <<< "$2"
}

#read -a KEY_ARRAY <<< "${keys}"

#=======================================
# Main
#=======================================

#
# Validate parameters
echo_info "Configs:"
echo_details "* smtp_server: ${smtp_server}"
echo_details "* sender_email: ${sender_email}"
echo_details "* sender_password: ${sender_password}"
echo_details "* certificate_file: ${certificate_file}"
echo_details "* host: ${host}"
echo_details "* port: ${port}"
echo_details "* validation: ${validation}"
echo_details "* notification_target: ${notification_target}"
echo_details "* project: ${project}"

validate_required_input "smtp_server" $smtp_server
validate_required_input "sender_email" $sender_email
validate_required_input "sender_password" $sender_password
validate_required_input "certificate_file" $certificate_file
validate_required_input "host" $host
validate_required_input "port" $port
validate_required_input "validation" $validation
validate_required_input "notification_target" $notification_target
validate_required_input "project" $project

SMTP_SERVER=$smtp_server
HOST=$host
PORT=$port
FILE=$certificate_file
EXPIRATION_SPAN=$validation
PROJECT=$project
SENDER=$sender_email
RECEIVER=$notification_target

function mailer {
    SMTP_ADDRESS="$1"
    FROM="$2"
    TO="$3"
    SUBJECT="$4"
    BODY="$5"
    SMTP_PASSWORD="$6"
    DATE="$(date)"

    TEMP_FILE="temp.txt"

    if [ -f $TEMP_FILE ]; then
        rm $TEMP_FILE
    fi

    echo "From: $FROM" > $TEMP_FILE
    echo "To: $TO" >> $TEMP_FILE 
    echo "Subject: $SUBJECT" >> $TEMP_FILE
    echo "Date: $DATE" >> $TEMP_FILE
    echo "" >> $TEMP_FILE
    echo "$BODY" >> $TEMP_FILE

    echo_info "Sending email to: $TO, from $FROM"
    curl --url "$SMTP_ADDRESS" --ssl-reqd \
      --mail-from "$FROM" \
      --mail-rcpt "$TO" \
      --user "$FROM:$SMTP_PASSWORD" \
      -T $TEMP_FILE

    rm $TEMP_FILE
}

function notify_error {
    FROM="$1"
    TO="$2"
    MESSAGE="$3"

    echo_info "$MESSAGE"
    mailer "$SMTP_SERVER" "$FROM" "$TO" "TLS Certificate issue on $PROJECT" "$MESSAGE" "$sender_password"
}

# This code expects the certificate being compared to be the same as the certificate
# coming from the browser. If it is not the case, please use other scripts
echo_info "Decoding certificate"
CERTIFICATE_ELEMENT="$(cat $FILE | openssl base64)"

echo_info "Decoding connection"
# This call basically fetches the certificate data from the server
CONNECTION_ELEMENT="$(echo | openssl s_client -servername $HOST -connect $HOST:$PORT -showcerts </dev/null 2>/dev/null | openssl x509 -text | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sed '1d;$d')"

# This is a literal comparison between the certificate file used on TLS connection
# and the one provided to this script
if [ "$CERTIFICATE_ELEMENT" != "$CONNECTION_ELEMENT" ]; then
    notify_error $SENDER $RECEIVER "Invalid certificate"
    exit 1
fi

echo_info "Valid certificate"
echo_info "--"
echo_info "Checking dates:"

CURRENT_MONTH="$(date +"%m")"
CURRENT_YEAR="$(date +"%Y")"
echo_info "Current date: $CURRENT_MONTH $CURRENT_YEAR"

# Simple logic to use openssl to fetch and load the expire date of the certificate used
HOT_KEY="notAfter="
NOT_AFTER_DATE="$(echo | openssl s_client -servername $HOST -connect $HOST:$PORT 2>/dev/null | openssl x509 -noout -dates | grep $HOT_KEY)"
CLEAN_DATE="$(echo ${NOT_AFTER_DATE//$HOT_KEY/})"

EXPIRE_MONTH="$(echo $CLEAN_DATE | awk '{print $1}' | awk 'BEGIN{months="  JanFebMarAprMayJunJulAugSepOctNovDec"}{print index(months,$0)/3}')"
EXPIRE_YEAR="$(echo $CLEAN_DATE | awk '{print $4}')"
echo_info "Expiration date: $EXPIRE_MONTH $EXPIRE_YEAR"

if [ "$CURRENT_YEAR" -gt "$EXPIRE_YEAR" ]; then
    notify_error $SENDER $RECEIVER "Certificate for the host $HOST, used on $PROJECT already expired"
    exit 1
fi

# This date calculation do not consider the day of the month, only the months itself
DATE_DIFF=$(( ($EXPIRE_YEAR - $CURRENT_YEAR) * 12 + (10#$EXPIRE_MONTH - 10#$CURRENT_MONTH) ))

if [[ "$DATE_DIFF" -lt "$EXPIRATION_SPAN" || "$DATE_DIFF" -eq "$EXPIRATION_SPAN" ]]; then
    notify_error $SENDER $RECEIVER "The certificate for the host $HOST, used on $PROJECT is close to expire. ($DATE_DIFF months)"
    exit 1
else
    echo_info "The certificate for the host $HOST, used on $PROJECT expires in $DATE_DIFF months"
    exit 0
fi