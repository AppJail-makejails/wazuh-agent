# Wazuh agent

The Wazuh agent is a single and lightweight monitoring software. It is a multi-platform component that can be deployed to laptops, desktops, servers, cloud instances, containers, or virtual machines. It provides visibility into the endpoint's security by collecting critical system and application records, inventory data, and detecting anomalies.

wazuh.com

![wazuh agent logo](https://i.ibb.co/KbQJHR3/Wazuh-agent.png)

## Goals

The principal goal of this Makejail is to deploy Wazuh agent on FreeBSD easily. Take on mind this container as is, is for testing/learning purpose and it is not recommended for production because it has a minimal configuration.

![wazuh agent dashboard 1](https://i.ibb.co/yy2Wyq8/wazuh-dashboard-agent-1.png)

![wazuh agent dashboard 2](https://i.ibb.co/hLyhNc1/wazuh-dashboard-agent-2.png)

## Requirements

Before you can install wazuh-agent using this Makejail you need a working wazuh-manager running and some other configurations. For deploy a wazuh single-node cluster (including wazuh-manager) you can use the [wazuh](https://github.com/AppJail-makejails/wazuh) Makejail. For testing purpose you can use the same FreeBSD host for install wazuh-manager and wazuh-agent.

### Enable Packet filter

We need to add some lines to `/etc/rc.conf`:

```console
# sysrc pf_enable="YES"
# sysrc pflog_enable="YES"
# cat << "EOF" >> /etc/pf.conf
nat-anchor 'appjail-nat/jail/*'
nat-anchor "appjail-nat/network/*"
rdr-anchor "appjail-rdr/*"
EOF
# service pf reload
# service pf restart
# service pflog restart
```

`rdr-anchor` is necessary for use dynamic redirect from jails.

### Enable forwarding

```console
# sysrc gateway_enable="YES"
# sysctl net.inet.ip.forwarding=1
```

### Bootstrap a FreeBSD version

Before you can begin creating containers, AppJail needs to fetch and extract components for create jails. If you are creating FreeBSD jails it must be a version equal or lesser than your host version.

```console
# appjail fetch
```

### Create a virtualnet

```console
# appjail network add wazuh-net 10.0.0.0/24
```

It will create a bridge named `wazuh-net` on which the epair interfaces will be attached. By default, this Makejail will use NAT for Internet outbound. Do not forget to add a `pass` rule in your `/etc/pf.conf` because this Makejail will try to download and install packages and some other resources.

```
pass out quick on wazuh-net inet proto { tcp udp } from 10.0.0.3 to any
```

## Create a lightweight container system

Create a container named `agent01` with a private IP address `10.0.0.3`. Take on mind that the IP address must be part of `wazuh-net` network.

```console
# appjail makejail -f gh+AppJail-makejails/wazuh-agent -j agent01 -- --network wazuh-net --agent_ip 10.0.0.3 --agent_name agent01 --server_ip 10.0.0.2 --enrollment managerpasswordenrollment
```

When it is done, `agent01` (`10.0.0.3`) will try connect to wazuh-manager (`10.0.0.2`) for auth process. Both are in the `wazuh-net` virtualnet.

## License

This project is licensed under the BSD-3-Clause license.
