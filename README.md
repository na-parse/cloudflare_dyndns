# cloudflare_DynDNS

Python-based script to automate Dynamic DNS WAN IP assignment updates for
Cloudflare-hosted DNS records. Built because the UniFi built-in Dynamic DNS does
not behave well with my configuration.

Primarily intended for personal use, but if someone else wants to use it, feel
free to submit feedback/issues/etc. on the GitHub page:
https://github.com/na-parse/cloudflare_dyndns

## Configuration

Create a `.config` file in the same directory as the `cfddns.py` script.
Configuration is defined in JSON format:

```json
{
    "CF_API_TOKEN": "<cloudflare_api_token>",
    "RECORDS": [
        {"domain": "example.net", "record": "vpn"},
        {"domain": "example.net", "record": "example.net"},
        {"domain": "example.net", "record": "wanip.example.net"}
    ],
    "TIME_TO_NOTIFY": 604800,
    "SENDFROM": "dns-monitor@example.com",
    "SENDTO": "sysops@example.com"
}
```

### Cloudflare API Token

The API token must have view and edit permissions for all domains being
monitored and updated by `cfddns`. No support for per-domain tokens is planned
at this time.

### RECORDS

```json
{ "domain": "<domain>", "record": "<record>" }
```

- `domain`: The exact domain name as shown in your Cloudflare console.
- `record`: Can be specified in three ways:
  - `hostname` — Hostname for the DNS A record to be updated
  - `example.com` — Specify the domain/zone name to set the root A record
  - `hostname.example.com` — Fully qualified hostname

Embedded subdomains are **not supported**. For example:

```json
{"domain": "example.net", "record": "vpn.external"}
```

is invalid.

### Monitoring Values

- `TIME_TO_NOTIFY`: Integer value in seconds specifying how long `cfddns` should
  wait before sending a heartbeat email to confirm it is still running as
  scheduled. Example: `604800` seconds = 7 days.
- `SENDFROM`: Email address used in the `From:` field when sending emails.
- `SENDTO`: Recipient email address for update and heartbeat notifications.

## Usage

- `cfddns.py` — Perform Dynamic DNS monitoring and updates for configured
  records
- `cfddns.py verbose` — Enable verbose debug messaging
- `cfddns.py show` — Display the current configuration

## Operation

Configure your preferred scheduler (most likely `cron`) to run
`cfddns.py monitor` at your desired interval for maintaining dynamic DNS
entries. A 15-minute interval is generally sufficient:

```bash
*/15 * * * * /path/to/cloudflare_dyndns/cfddns.py
```

Records are updated if the external IP address does not match, and they are
created if they do not exist. No need to pre-create records in the Cloudflare
dashboard.

### Email Notifications

The monitor uses the system-local `/usr/sbin/sendmail` to send an email after
performing updates so you know what was changed. It also includes a heartbeat
function: if the last email sent exceeds the configured `TIME_TO_NOTIFY` value,
a heartbeat email is generated to confirm the monitor is still running. This
prevents surprises if the monitor stops working silently.

### Logging

The monitor stores a log file in the same directory as the `cfddns.py` script
called `cfddns_activity.log`.

## Why Not Use the Router’s Built-In Dynamic DNS?

My home network runs a UniFi stack from Ubiquiti, including a UniFi Dream
Machine Pro (UDM Pro) as the primary gateway device.

The UniFi Network Controller/UDM Pro stack’s Dynamic DNS service does not
reliably update or set root records for my domains. Rather than troubleshoot a
service I cannot fully control, I wrote my own monitoring and updating service.

UniFi is great when it works. When it doesn’t—just do it yourself.

## Notes / Appendix

### Setting up SMTP Relay via Gmail

If you don’t have SMTP relay/email working on your Linux system, see Linode’s
guide on setting up sendmail relay via Gmail using Postfix and App Passwords:

- https://www.linode.com/docs/guides/configure-postfix-to-send-mail-using-gmail-and-google-workspace-on-debian-or-ubuntu/

### The UniFi Problem: More Detail

The built-in `inadyn` process fails whenever I add more than one dynamic DNS
entry on the WAN configuration. The
`/run/ddns-eth8-inadyn.conf` file looks correct, and the API keys are stored
normally, but when it runs, many 400/403 authentication errors appear.

```bash
inadyn -n -1 --force -f /run/ddns-eth8-inadyn.conf
```

It’s unclear whether it uses the wrong provider module or mishandles the API
key. Instead of debugging `inadyn` on the UDM Pro, I built this project. The
result is a cleaner, more reliable, and easily cloud-init–deployable solution
for DNS/Pi-hole builds.

### Cloudflare Records Response Example

`get_record()` response:

```json
{
  "id": "123456782345678790a",
  "name": "wanip.example.com",
  "type": "A",
  "content": "192.0.2.2",
  "proxiable": true,
  "proxied": false,
  "ttl": 300,
  "settings": {},
  "meta": {},
  "comment": null,
  "tags": [],
  "created_on": "2025-09-01T21:53:24.311897Z",
  "modified_on": "2025-09-01T21:53:24.311897Z"
}
```