#!/bin/sh

. /scripts/lib.subr

sync_localtime()
{
    exec_cmd_stdout "cp /etc/localtime /var/ossec/etc/localtime"
}

create_active_responses()
{
    exec_cmd_stdout "touch /var/ossec/logs/active-responses.log"
    exec_cmd_stdout "chmod 740 /var/ossec/logs/active-responses.log"
}

create_syslog()
{
    exec_cmd_stdout "touch /var/log/syslog"
    exec_cmd_stdout "chmod 740 /var/log/syslog"
}

remove_authorization_path()
{
    gsed -i '/<authorization_pass_path>/d' /var/ossec/etc/ossec.conf
}

mount_files()
{
    if [ -e "/wazuh-config-mount" ]; then
        info "Identified Wazuh configuration files to mount..."
        exec_cmd_stdout "cp -va /wazuh-config-mount/ /var/ossec"
    else
        info "No Wazuh configuration files to mount..."
    fi
}

set_manager_conn() {
    echo "ossec.conf configuration"
    gsed -i "s#<address>CHANGE_MANAGER_IP</address>#<address>$WAZUH_MANAGER_SERVER</address>#g" /var/ossec/etc/ossec.conf
    gsed -i "s#<port>CHANGE_MANAGER_PORT</port>#<port>$WAZUH_MANAGER_PORT</port>#g" /var/ossec/etc/ossec.conf
    gsed -i "s#<manager_address>CHANGE_ENROLL_IP</manager_address>#<manager_address>$WAZUH_REGISTRATION_SERVER</manager_address>#g" /var/ossec/etc/ossec.conf
    gsed -i "s#<port>CHANGE_ENROLL_PORT</port>#<port>$WAZUH_REGISTRATION_PORT</port>#g" /var/ossec/etc/ossec.conf
    gsed -i "s#<agent_name>CHANGE_AGENT_NAME</agent_name>#<agent_name>$WAZUH_AGENT_NAME</agent_name>#g" /var/ossec/etc/ossec.conf
    gsed -i "s#<groups>CHANGE_AGENT_GROUPS</groups>#<groups>$WAZUH_AGENT_GROUPS</groups>#g" /var/ossec/etc/ossec.conf
    [ -n "$WAZUH_REGISTRATION_PASSWORD" ] && \
    echo "$WAZUH_REGISTRATION_PASSWORD" > /var/ossec/etc/authd.pass && \
    chown root:wazuh /var/ossec/etc/authd.pass && \
    chmod 640 /var/ossec/etc/authd.pass
}

entrypoint_scripts()
{
    # It will run every .sh script located in entrypoint-scripts folder in lexicographical order
    if [ -d "/entrypoint-scripts/" ]; then
        for script in `ls /entrypoint-scripts/*.sh | sort -n`; do
            /bin/sh "$script"
        done
    fi
}

sync_localtime

create_active_responses

create_syslog

remove_authorization_path

mount_files

set_manager_conn

entrypoint_scripts
