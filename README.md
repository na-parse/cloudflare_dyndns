# cloudflare_DynDNS

Nathan's tool(s?) for managing dynamic DNS with cloudflare as the DNS provider


## Configuration

Create the `.config` file in the same directory as the script `monitor_dyn_dns.py`.  Configuration is defined in JSON format:

```json
{
    "CF_API_TOKEN": "<cloudflare_api_token>",
    "RECORDS": [
        {"domain": "example.net", "record": "example.net"},
        {"domain": "example.net", "record": "wanip.example.net"},
        {"domain": "example.net", "record": "vpn"}
    ],
    "TIME_TO_NOTIFY": 604800,
    "SENDFROM": "dns-monitor@example.com",
    "SENDTO": "sysops@example.com"
}
```

The record names are expected in a Fully Qualified Domain Name format and you specify the root A record as the domain name as shown by the example configuration `{"domain": "example.net", "record": "example.net"}` while other records can be specified in FQDN format, or as the hostname and the updater will internally add the domain (`vpn` will be expanded to `vpn.example.net`).

Embedded subdomains are not supported: `{"domain": "example.net", "record": "vpn.external"}`.

## Operation

Schedule the `monitor_dyn_dns.py` to run at your desired interval for maintaining your dynamic DNS entries.  When in doubt, `*/15 * * * *` is probably good enough.

The monitor uses https://api.ipify.org to get the external IP and then checks all configured DNS records to verify that have the correct/current IP address.

Records are updated if the External IP address does not match, and they are created if they do not exist.  No need to enter your CF dashboard ahead of time.

The monitor will also use the system local `/usr/sbin/sendmail` to send an email after performing updates so you know what it did/changed.  Additionally it includes a heartbeat function.  If the last email sent from the monitor exceeds the configuration value `TIME_TO_NOTIFY` in seconds, a heartbeat email will be generated to let you know the monitor is still working and running.  The heartbeat ensures you don't get surprised that the monitor stopped working three months ago and none of your IPs were ever updated.

## Why? Doesn't your GW do this?

My home network runs a heavy Unifi stack from Ubiquity, including a Unifi Dream Machine Pro (UDM Pro) as the primary gateway device.

The Unifi Network Controller/UDM Pro stack's Dynamic DNS service does not reliably update or set root records for my domains.  Rather than mess around with a broken service I can't control or keep fixed even if I fix it once, I figured I'd write my own monitoring and updating service.

Unifi stuff is cool when it works, and when it doesn't, just... do it yourself.  For real.

## Stuff

Anything else I think of will go here if I need to.


## Notes/Appendix

### CloudFlare Records Response Structures

`get_record()`:
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