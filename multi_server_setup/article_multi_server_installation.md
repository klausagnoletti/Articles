# How to set up a CrowdSec multi-agent installation


### Introduction

The CrowdSec agent is able to act as a HTTP rest API server to collect signals from other CrowdSec agents. This enables one CrowdSec agent to act as a 'main' agent in the sense that it both collects signals from other agents, shares information about detected attacks with other local agents, sends signals to CrowdSec's central API (CAPI) as well as receiving blocklists via CAPI and distributing those to the other agents.

This ability to function in a distributed setup also means that mitigation doesn't have to take place on the same agent as detection. Mitigation is done using [bouncers](https://docs.crowdsec.net/Crowdsec/v1/bouncers/). Bouncers rely on the HTTP REST API served by the 'main' CrowdSec agent.

In fact CrowdSec is what we call API-driven meaning that all components of CrowdSec communicates via HTTP rest API so that it's able to be deployed in a fully distributed way, enabling it to scale to fit any size of infrastructure.

In this article we will call the 'main' agent the LAPI server.

### Goals

In this article we'll describe how to deploy CrowdSec in a multi-agent setup with one agent sharing signals with others.

> Insert network diagram here

![](https://crowdsec.net/wp-content/uploads/2021/04/Capture-de%CC%81cran-2021-04-26-a%CC%80-17.34.06-3486723453-1619451504593.png)

Both `agent-2` and `agent-3` are meant to host services. You can take a look on our [Hub](https://hub.crowdsec.net/)  to know which services CrowdSec can help you secure. Last but not least, `agent-1` is meant to host the following local services:

* the local API needed by bouncers
* the database fed by both the three local CrowdSec agents and the online CrowdSec blocklist service.
  As `agent-1` is serving the local API, we will call it the LAPI server.

We choose to use a MariaDB backend for CrowdSec database in order to allow better performance and to enable the possibility of high availability which can be implemented later.

Furthermore this post will cover attack mitigation for hosted services on `agent-2` and `agent-3` using CrowdSec bouncers.

## Prerequisites

* Two Internet-facing preinstalled Debian servers hosting services. From now on, we will refer to these servers by `agent-2` and `agent-3` .
* One non Internet facing preinstalled Debian server. From now on we will refer to this server by `agent-1`. Let's assume that `agent-1'`s  ip is 10.0.0.1. (no internet connection on this server is not a strict requirement).
* A local network connecting all three servers

## Step 1: CrowdSec installation

Let's install CrowdSec on every single server, following the [CrowdSec installation guide](https://docs.crowdsec.net/Crowdsec/v1/getting_started/installation/#install-using-crowdsec-repository).

```console
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash

sudo apt install crowdsec
```

Note: In general we don't recommend downloading scripts from the internet and execute them with root permissions on production systems. In a test setup like this where the risk is low, it'll do.

We now have three standard CrowdSec installations running.

## Step 2 (Optional): Switch the database backend to MySQL (same as MariaDB) on agent-1

```console
sudo apt install mariadb-server
```

First we have to connect to the database as the mysql root user.

```console
$ sudo mysql
```

Thanks to the [MySQL CrowdSec documentation](https://doc.crowdsec.net/docs/next/local_api/database#mysql-and-mariadb), we can now initialize the database.

```mysql
mysql> CREATE DATABASE crowdsec;
mysql> CREATE USER 'crowdsec'@'%' IDENTIFIED BY '<password>';
mysql> GRANT ALL PRIVILEGES ON crowdsec.* TO 'crowdsec'@'%';
mysql> FLUSH PRIVILEGES;
```

Now let's make CrowdSec know about this new database backend. To achieve this, we will have to update the `db_config` section of the `/etc/crowdsec/config.yaml` file.

```yaml
db_config:
  log_level: info
  type:	mysql
  user: crowdsec
  password: "<password>"
  db_name: crowdsec
  host: 127.0.0.1
  port: 3306
```

After registering the local machine again in the database, we are able to restart CrowdSec:

```console
$ sudo cscli machines add -a
$ sudo systemctl restart crowdsec
```

## Step 3: Make `agent-2` and `agent-3` report to LAPI server (aka `agent-1`)

First we have to configure CrowdSec on LAPI server to accept connections from `agent[123]`. Please ensure that your firewall allows connections from `agent-2` and `agent-3`on LAPI server's port 8080.

Let's configure the LAPI server as well as the agent configuration on that server (`agent-1`). Modify both `/etc/crowdsec/config.yaml` and `/etc/crowdsec/local_api_credentials.yaml`.

For `/etc/crowdsec/config.yaml` edit the API section. It's only a matter of updating the listening ip from localhost to all ips:

```yaml
api:
  client:
    insecure_skip_verify: false
    credentials_path: /etc/crowdsec/local_api_credentials.yaml
  server:
    log_level: info
    listen_uri: 0.0.0.0:8080
    profiles_path: /etc/crowdsec/profiles.yaml
    online_client: # CrowdSec API credentials (to push signals and receive bad IPs)                                                                        
      credentials_path: /etc/crowdsec/online_api_credentials.yaml
```

For `/etc/crowdsec/local_api_credentials.yaml` on all three servers we have to change the configured URL:

```yaml
url: http://10.0.0.1:8080/
login: <login>
password: <password>
```
Don't change login and password already present in the file.

After that we can restart CrowdSec:

```console
$ sudo systemctl restart crowdsec

```
Now we will configure the connections on `agent-2` and `agent-3`.
First we register to the lapi server on both `agent-2` and `agent-3`:

```console
$ sudo cscli lapi register -u http://10.0.0.1:8080
```

By default, the local api server is active on every CrowdSec agent installation. In this setup, we want to disable it on `agent-2` and `agent-3`. To achieve this, we need to tweak the CrowdSec agent systemd service file.

```console
$ sudo cp /lib/systemd/system/crowdsec.service /etc/systemd/system/crowdsec.service
```

Now edit `etc/systemd/system/crowdsec.service` and add the `-no-api` parameter to CrowdSec agent invocation on both `agent-2` and `agent-3`.

```
[Unit]
Description=Crowdsec agent
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=notify
Environment=LC_ALL=C LANG=C
PIDFile=/var/run/crowdsec.pid
ExecStartPre=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml -t
ExecStart=/usr/bin/crowdsec -c /etc/crowdsec/config.yaml -no-api
#ExecStartPost=/bin/sleep 0.1
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

We can now acknowledge the changes and restart CrowdSec once again.

```console
$ sudo systemctl daemon-reload
$ sudo systemctl restart crowdsec
```

Next thing to do is to allow `agent-2` and `agent-3` connections on `agent-1`.

```console
$ sudo cscli machines list
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 NAME                                              IP ADDRESS     LAST UPDATE           STATUS  VERSION                                                                 AUTH TYPE  LAST HEARTBEAT 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 3ac4e593172c4cdfb51cd8d8b2d9d5f2anhrb3Cl21kMkT6A  10.0.0.1  2022-08-25T18:44:27Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  password   37s            
 3ae4c4a86efc4a45abb75ce2c2a30057ST4IQonK81521ylV  10.0.0.2   2022-08-25T18:38:24Z  🚫                                                                              password   ⚠️  6m40s        
 caf1b0ce5e4f4a17a77ddad7c0100558SWr9eQgiovQNqf9w  10.0.0.3   2022-08-25T18:40:50Z  🚫                                                                              password   ⚠️  4m14s        
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

In this output, we can see two machines that are not yet validated. Let's validate them now.

```console
$ sudo cscli machines validate 9f3602d1c9244f02b0d6fd2e92933e75zLVg8zSRkyANxHbC
$ sudo cscli machines validate ac86209e6f9c4d7d8de43e2ea31fe28ebvde0vWDr46Mpd3L
```

Your client ids will be different so don't copy/paste those from this article. It won't work.


`agent-2` and `agent-3` are now allowed to push data to `agent-1` CrowdSec agent. It may be needed to restart CrowdSec on `agent-2` and `agent-3`.


On `agent-1`, the command `sudo cscli machines list` should now show three validated machines. Please list machines again to be sure:

```console
$ sudo cscli machines list
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 NAME                                              IP ADDRESS     LAST UPDATE           STATUS  VERSION                                                                 AUTH TYPE  LAST HEARTBEAT 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 3ac4e593172c4cdfb51cd8d8b2d9d5f2anhrb3Cl21kMkT6A  10.0.0.1  2022-08-25T18:47:27Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  password   10s            
 3ae4c4a86efc4a45abb75ce2c2a30057ST4IQonK81521ylV  10.0.0.2   2022-08-25T18:46:49Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  password   48s            
 caf1b0ce5e4f4a17a77ddad7c0100558SWr9eQgiovQNqf9w  10.0.0.3   2022-08-25T18:47:31Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  password   6s             
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```
## Step 4: Set up TLS authentification

We now have three agents able to communicate to the main LAPI server using clear-text communication. In a secure production environment this is a no-go so we have to change to a certificate based infrastructure. In this example we will be creating all certificates ourselves. In a real production environment this will be done by your PKI. The procedure will vary so we won't cover that in our article; just the procedure of creating test certificates and configuring each agent to use those.

We will be creating certificates on LAPI server aka `agent-1`. For this we will be using the tool [cfssl](https://github.com/cloudflare/cfssl). Luckily it's available in Debian:
```
$ sudo apt install golang-cfssl
```
Next, create a directory for certificate config files
```
$ mkdir cfssl
```
Create the following files inside that directory

```profiles.json```
```json
{
    "signing": {
      "default": {
        "expiry": "8760h"
      },
      "profiles": {
        "intermediate_ca": {
          "usages": [
              "signing",
              "digital signature",
              "key encipherment",
              "cert sign",
              "crl sign",
              "server auth",
              "client auth"
          ],
          "expiry": "8760h",
          "ca_constraint": {
              "is_ca": true,
              "max_path_len": 0, 
              "max_path_len_zero": true
          }
        },
        "server": {
          "usages": [
            "signing",
            "digital signing",
            "key encipherment",
            "server auth"
          ],
          "expiry": "8760h"
        },
        "client": {
          "usages": [
            "signing",
            "digital signature",
            "key encipherment", 
            "client auth"
          ],
          "expiry": "8760h"
        }
      }
    }
  }
```
`ca.json` defines basic properties of our CA:
```json
{
  "CN": "CrowdSec Test CA",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "FR",
    "L": "Paris",
    "O": "Crowdsec",
    "OU": "Crowdsec",
    "ST": "France"
  }
 ]
}
```
`intermediate.json` defines our intermediate cert:
```json
{
    "CN": "CrowdSec Test CA Intermediate",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "Crowdsec",
      "OU": "Crowdsec Intermediate",
      "ST": "France"
    }
   ],
   "ca": {
    "expiry": "42720h"
  }
  }
```

With `server.json` things start to get a little complicated if you're using a different subnet than in our example (you probably are) as you would need to change the ip that the other agents are connecting to accordingly.

```json
{
    "CN": "localhost",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "Crowdsec",
      "OU": "Crowdsec Server",
      "ST": "France"
    }
    ],
    "hosts": [
      "127.0.0.1",
      "localhost"
      "10.0.0.1"
    ]
  }
```
Lastly here's the certs of agents and bouncers. Each agent and bouncer should have their own cert but I'll only paste one of each so you will have to change the CN of each to match.

``agent[123].json``
```json
{
    "CN": "agent[123]",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "Crowdsec",
      "OU": "agent-ou",
      "ST": "France"
    }
    ]
  }
```
`bouncer-agent[123].json`
```json
{
    "CN": "bouncer-agent-[123]",
    "key": {
      "algo": "rsa",
      "size": 2048
    },
    "names": [
    {
      "C": "FR",
      "L": "Paris",
      "O": "Crowdsec",
      "OU": "bouncer-ou",
      "ST": "France"
    }
    ]
  }
```

Next we need to create CA and certs:

CA

```console
$ cfssl gencert --initca ./cfssl/ca.json 2>/dev/null | cfssljson --bare "/tmp/ca"
```

Intermediate certificate user to sign clients certs (agents and bouncers)

```console
$ cfssl gencert --initca ./cfssl/intermediate.json 2>/dev/null | cfssljson --bare "/tmp/inter"
$ cfssl sign -ca "/tmp/ca.pem" -ca-key "/tmp/ca-key.pem" -config ./cfssl/profiles.json -profile intermediate_ca "/tmp/inter.csr" 2>/dev/null | cfssljson --bare "/tmp/inter"
```

Server side certificate

```console
$ cfssl gencert -ca "/tmp/inter.pem" -ca-key "/tmp/inter-key.pem" -config ./cfssl/profiles.json -profile=server ./cfssl/server.json 2>/dev/null | cfssljson --bare "/tmp/server"
```

Client certificate for the agent certificates

```console
$ cfssl gencert -ca "/tmp/inter.pem" -ca-key "/tmp/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/agent[123].json 2>/dev/null | cfssljson --bare "/tmp/agent[123]"
```

Client certificate for the bouncer certficates

```console
$ cfssl gencert -ca "/tmp/inter.pem" -ca-key "/tmp/inter-key.pem" -config ./cfssl/profiles.json -profile=client ./cfssl/bouncer.json 2>/dev/null | cfssljson --bare "/tmp/bouncer"
```

For verification of certs on LAPI server we need both CA and intermediate cert. These should be concatinated into a full chain cert:

```console
$ cat /tmp/ca.pem /tmp/inter.pem > /tmp/fullchain.pem
```

For verification of certs on agents we need a different CA since we need to be able to validate both the LAPI server as well as any internal crowdsec certificates (more speficially the CAPI server's cert at api.crowdsec.net). This CA is created by concatinating the existing CA with the fullchain.pem we just created:

```console
$ cat /tmp/fullchain.pem /etc/ssl/certs/ca-certificates.crt > /tmp/ca-combined.pem
```

Next we want to copy all certs to `/etc/ssl/certs`.

```console
$ sudo cp /tmp/*.pem /etc/ssl/certs
```

Certificates for `agent[123]`, `bouncer-agent[123]` as well as `ca-combined.pem` needs to be copied to `/etc/ssl/certs` on the corresponding server. I suggest using `scp`for this.

To configure LAPI server update `/etc/crowdsec/config.yaml` to include the certificates we just created:

```yaml
api:
 server:
   tls:
    cert_file: /etc/ssl/certs/server.pem #Server side cert
    key_file: /etc/ssl/certs/server-key.pem #Server side key
    ca_cert_path: /etc/ssl/fullchain.pem #certificate used to verify client certs
    bouncers_allowed_ou: #OU allowed for bouncers
      - bouncer-ou
    agents_allowed_ou: #OU allowed for agents
      - agent-ou
```


One thing that may surprise you here is that `agent-1` in this sense needs to be configured to connect to itself, so to speak. 
In this sense the configuration of `agent-1`, `agent-2` and `agent-3` are the same. If you, like me, like them to be identical when you do `cscli machines list` configure `agent-1`to connect to the real network ip of the box (rather than `localhost` / `127.0.0.1`). Basically you need to edit `/etc/crowdsec/local_api_credentials.yaml` like this:

```yaml
url: https://10.0.0.1:8080
ca_cert_path: /etc/ssl/certs/ca-combined.pem #certificate used to verify client certs
key_path: /etc/ssl/certs/agent[123]-key.pem #Client key.
cert_path: /tmp/agent[123].pem #Client cert
```

Keep in mind to note the corresponding agent cert in the config of each agent (and not literally type `agent[123]`on each. That won't work).

After editing files on LAPI server and each agent, restart CrowdSec with `sudo systemctl restart crowdsec` on all nodes and watch `/var/log/crowdsec.log` on LAPI server to make sure everything works:

```
$ sudo tail -f /var/log/crowdsec.log
```

```log
time="29-08-2022 10:42:58" level=info msg="TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification" component=tls-auth type=agent
time="29-08-2022 10:42:58" level=warning msg="no crl_path, skipping CRL check" component=tls-auth type=agent
time="29-08-2022 10:42:58" level=info msg="machine agent-1@10.0.0.1 not found, create it"
time="29-08-2022 10:43:46" level=info msg="TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification" component=tls-auth type=agent
time="29-08-2022 10:43:46" level=warning msg="no crl_path, skipping CRL check" component=tls-auth type=agent
time="29-08-2022 10:44:19" level=info msg="machine agent-2@10.0.0.2 not found, create it"
time="29-08-2022 10:44:19" level=info msg="TLSAuth: no OCSP Server present in client certificate, skipping OCSP verification" component=tls-auth type=agent
time="29-08-2022 10:44:19" level=warning msg="no crl_path, skipping CRL check" component=tls-auth type=agent
time="29-08-2022 10:44:19" level=info msg="machine agent-3@10.0.0.3 not found, create it"
```


To verify all agents are connected do `sudo cscli machines list`:

```
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
 NAME                   IP ADDRESS     LAST UPDATE           STATUS  VERSION                                                                 AUTH TYPE  LAST HEARTBEAT 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
 agent-1@10.0.0.1  10.0.0.1  2022-08-31T08:21:14Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  tls        4s             
 agent-2@10.0.0.2   10.0.0.2   2022-08-31T08:20:31Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  tls        47s            
 agent-3@10.0.0.3   10.0.0.3   2022-08-31T08:20:51Z  ✔️       v1.4.1-debian-pragmatic-linux-e1954adc325baa9e3420c324caabd50b7074dd77  tls        27s            
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

## Step 5: Set up Mitigation

Now we want to install mitigation on our internet-facing servers. We'll set up firewall bouncers using TLS certificates so we won't need an API key (which we would have needed using cleartext communication). First install bouncers on each node:

```console
$ sudo apt install crowdsec-firewall-bouncer-nftables
```

Configure `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`:

```yaml
api_url: https://172.31.46.130:8080/
cert_path: /etc/ssl/certs/bouncer-agent-[123].pem
key_path: /etc/ssl/certs/bouncer-agent-[123]-key.pem
ca_cert_path: /etc/ssl/certs/fullchain.pem
#api_key: <api key>
```

Restart the firewall bouncer:

```console
$ sudo systemctl restart crowdsec-firewall-bouncer
```

Watch the `/var/log/crowdsec-firewall-bouncer.log` for any error messages. If everything works you'll just see this:

```log
time="31-08-2022 09:45:03" level=info msg="Using cert auth with cert '/etc/ssl/certs/bouncer-agent-1.pem' and key '/etc/ssl/certs/bouncer-agent-1-key.pem'"
time="31-08-2022 09:45:03" level=info msg="Using CA cert '/etc/ssl/certs/fullchain.pem'"
```

To make sure all bouncers are added, list them using `cscli`

```console
klaus@server1:/tmp$ sudo cscli bouncers list
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 NAME                           IP ADDRESS     VALID  LAST API PULL         TYPE                       VERSION                                                                AUTH TYPE 
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 bouncer-agent-1@10.0.0.1  10.0.0.1  ✔️      2022-08-31T10:18:33Z  crowdsec-firewall-bouncer  v0.0.25-rc1-debian-pragmatic-8e00af2c9e83af22deab8c0c49a4ad9b8fc57a3f  tls       
 bouncer-agent-2@10.0.0.2   10.0.0.2   ✔️      2022-08-31T10:18:29Z  crowdsec-firewall-bouncer  v0.0.25-rc1-debian-pragmatic-8e00af2c9e83af22deab8c0c49a4ad9b8fc57a3f  tls       
 bouncer-agent-3@10.0.0.3   10.0.0.3   ✔️      2022-08-31T10:18:25Z  crowdsec-firewall-bouncer  v0.0.25-rc1-debian-pragmatic-8e00af2c9e83af22deab8c0c49a4ad9b8fc57a3f  tls       
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

## Conclusion and perspectives

We described how to setup a CrowdSec multi-server installation where all communication is TLS authenticated and encrypted. The resource overhead on `agent-2` and `agent-3` is quite limited as most of the tasks are deported to `agent-1`. This allows to grow the installation just by issuing certificates for new agents and bouncers and configuring those on any new nodes. Quite easy.

Obviously, there are caveats in this setup:

* The CrowdSec database is not highly available. Hence, the CrowdSec agent on `agent-1` is a single point of failure.
* Monitoring or alerting is not covered in this article. CrowdSec allows very powerful monitoring through the CrowdSec console, a prometheus scraper or a built-in instance of Metabase