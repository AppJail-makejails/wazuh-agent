# Wazuh (agent)

The Wazuh agent is installed on endpoints such as laptops, desktops, servers, cloud instances, or virtual machines. They provide threat prevention, detection, and response capabilities. They run on operating systems such as FreeBSD, Linux, Windows, macOS, Solaris, AIX, and HP-UX.

wazuh.com

<img src="https://upload.wikimedia.org/wikipedia/commons/c/c3/Wazuh-Logo-2022.png?20230817165159" width="60%" height="auto" alt="wazuh logo">

## How to use this Makejail

### Deploy using appjail-director

```yaml
options:
  - virtualnet: ':<random> default'
  - nat:
  - osversion: '14.3-RELEASE'
  - copydir: 'user-files'
  - file: '/usr/local/etc/pkg/repos/Latest.conf'
  - file: '/wazuh-config-mount'
  - file: '/entrypoint-scripts'
services:
  wazuh-agent:
    name: wazuh-agent
    makejail: gh+AppJail-makejails/wazuh-agent
    environment:
      - WAZUH_MANAGER_SERVER: '10.0.0.80'
      - WAZUH_REGISTRATION_PASSWORD: 'fhlc0egBAfx0vZMWoJig4bhZjPgxG8tKEM0yTBfd50Q'
      - WAZUH_AGENT_NAME: 'wazuh-agent'
```

**user-files/usr/local/etc/pkg/repos/Latest.conf**:

```
FreeBSD: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
FreeBSD-kmods: {
  enabled: no
}
```

**user-files/wazuh-config-mount/etc/ossec.conf**:

```
<!--
  Wazuh - Agent - Default configuration.
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->

<ossec_config>
  <client>
    <server>
      <address>CHANGE_MANAGER_IP</address>
      <port>1514</port>
      <protocol>udp</protocol>
    </server>
    <config-profile>freebsd, freebsd15</config-profile>
    <crypto_method>aes</crypto_method>
      <enrollment>
        <agent_name>CHANGE_AGENT_NAME</agent_name>
      </enrollment>
  </client>

  <client_buffer>
    <!-- Agent buffer options -->
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
    <system_audit>/var/ossec/etc/shared/cis_freebsd15.yml</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-debian-8-ds.xml">
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
    <content type="oval" path="cve-debian-oval.xml"/>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>

    <!-- Database synchronization settings -->
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- File types to ignore -->
    <ignore type="sregex">.log$|.swp$</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <!-- Nice value for Syscheck process -->
    <process_priority>10</process_priority>

    <!-- Maximum output throughput -->
    <max_eps>50</max_eps>

    <!-- Database synchronization settings -->
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/cron</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/daemon.log</location>
  </localfile>
    
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/debug.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/userlog</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>(netstat -n -f inet && netstat -n -f inet) | grep -e "udp" -e "tcp" | sed 's/\([[:alnum:]]*\)\ *[[:digit:]]*\ *[[:digit:]]*\ *\([[:digit:]\.]*\)\.\([[:digit:]]*\)\ *\([[:digit:]\.]*\).*/\1 \2 == \3 == \4/' | sort -k4 -g | sed 's/ == \(.*\) ==/.\1/'</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
    <frequency>360</frequency>
  </localfile>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
```

**user-files/entrypoints-scripts/001-fix-permissions.sh**:

```sh
#!/bin/sh

chmod 770 /var/ossec/etc
chown wazuh:wazuh /var/ossec/etc
chmod 660 /var/ossec/etc/ossec.conf
chown root:wazuh /var/ossec/etc/ossec.conf
```

### Special Mount Points

* `/wazuh-config-mount/`: When mounted, the files are copied as-is to `/var/ossec`.
* `/entrypoint-scripts/`: Can contain scripts that are executed in lexicographical order using `/bin/sh`.

### Environment

* `WAZUH_MANAGER_SERVER` (optional): If you have `<address>CHANGE_MANAGER_IP</address>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#address
* `WAZUH_MANAGER_PORT` (optional): If you have `<port>CHANGE_MANAGER_PORT</port>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#port
* `WAZUH_REGISTRATION_SERVER` (optional): If you have `<manager_address>CHANGE_ENROLL_IP</manager_address>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#manager-address
* `WAZUH_REGISTRATION_PORT` (optional): If you have `<port>CHANGE_ENROLL_PORT</port>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#enrollment-manager-port
* `WAZUH_AGENT_NAME` (optional): If you have `<agent_name>CHANGE_AGENT_NAME</agent_name>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#agent-name
* `WAZUH_AGENT_GROUPS` (optional): If you have `<groups>CHANGE_AGENT_GROUPS</groups>` in your `ossec.conf` configuration file, the value of this setting can be changed with the value of this environment variable. See also: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#groups
* `WAZUH_REGISTRATION_PASSWORD` (optional): When using passwords as an additional security measure in your wazuh-manager instance, you can use the `WAZUH_REGISTRATION_PASSWORD` environment variable.

## Notes

1. The ideas present in the [Docker image of Wazuh](https://github.com/wazuh/wazuh-docker) are taken into account for users who are familiar with it.
2. `/etc/localtime` file of the jail is copied to `/var/ossec/etc/localtime`, so it should exist.
3. `<authorization_pass_path>` is removed.
