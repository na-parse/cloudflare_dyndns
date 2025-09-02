#!/usr/bin/python3
'''
monitor_dyn_dns.py
-
Uses cloudflare API to perform 'dynamic DNS' operations to set and maintain
dynamic A record for owned domains to use the current WAN IP address.

Works by using the 'api.ipify.org' site to request to find the current external
WAN IP, then checks all configured domains for matching record settings.

Any configured records that do not match the current IP are updated.

Configuration file is '.config' and uses JSON to define:
    CF_API_TOKEN - str - API key value to use for cloudflare operations
    RECORDS - list - List format of records to dynamically update
        RECORDS_ITEM - dict - { 'domain': <domain>, 'record': <record_name> }
    TIME_TO_NOTIFY - int - Time (in seconds) between "I'm still running" emails
    SENDFROM - str - Sender email address
    SENDTO - str - Send-to email address

See README.md for further details on configuration
'''
import warnings
warnings.filterwarnings("ignore", module="urllib3")
import requests
import sys
import os
import json
import time
import subprocess
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigClass:
    def __init__(self, config_file: Path = None):
        if config_file is None:
            config_file = Path(__file__).parent / '.config'
        config_file = Path(config_file)
        if not config_file.is_file():
            die(f'Unable to find {str(config_file)}')
        try:
            with open(config_file, 'r') as f:
                conf_values = json.load(f)
            self.CF_API_TOKEN = conf_values['CF_API_TOKEN']
            self.RECORDS = conf_values['RECORDS']
            self.TIME_TO_NOTIFY = conf_values['TIME_TO_NOTIFY']
            self.SENDTO = conf_values['SENDTO']
            self.SENDFROM = conf_values['SENDFROM']
        except Exception as e:
            die(
                f'Error while reading/processing config file {str(config_file)}'
                f'\n--\n{e}'
            )            

class HistoryClass:
    def __init__(self, history_file: Path = None):
        if history_file is None:
            history_file = Path(__file__).parent / '.history'
        self.history_file = history_file
        self.data = self._load_history()
    
    def update(self,data_key,data_value) -> None:
        self.data[data_key] = data_value
        try:
            with open(self.history_file,'w') as f:
                _ = json.dump(self.data, f)
        except Exception as e:
            die(
                f'Error while updating history file: {str(self.history_file)}'
                f'\n--\n{e}'
            )

    def get(self,data_key, default_value: Any = None) -> Any:
        return self.data.get(data_key,default_value)

    def _load_history(self):
        data = {}
        history_file = Path(self.history_file)
        if history_file.exists():
            try:
                with open(history_file,'r') as f:
                    data = json.load(f)  
            except Exception as e:
                print(f'Issue with history file, resetting...')
                os.remove(history_file)
        return data

def die(msg: str, verbose: bool = True) -> None:
    if verbose: print(f'[FATAL] {msg}')
    exit(1)
        

def send_email(send_from: str, send_to: str, notice: str, msg: str):
    subject = f"[set_root_dns] {notice}"
    email_body = (
        f'To: {send_to}\n'
        f'From: {send_from}\n'
        f'Subject: {subject}\n'
        f'Content-Type: text/plain; charset="utf-8"\n'
        f'{msg}'
    )
    try:
        proc = subprocess.Popen(
            ["/usr/sbin/sendmail", "-t", "-oi"],
            stdin=subprocess.PIPE,
            text=True,
        )
        proc.communicate(email_body)
        if proc.returncode != 0:
            raise RuntimeError(f"sendmail exited with {proc.returncode}")
    except Exception as e:
        # Handle logging or fallback here
        print(f"Failed to send notification: {e}")
    # Update history to indicate the last time a message was sent
    history.update('lastsent',time.time())


def get_external_ip() -> str:
    r = requests.get("https://api.ipify.org?format=json", timeout=10)
    r.raise_for_status()
    return r.json()["ip"]

def get_zone_id(session, zone_name):
    r = session.get(
        "https://api.cloudflare.com/client/v4/zones",
        params={"name": zone_name},
    )
    r.raise_for_status()
    zones = r.json()["result"]
    if not zones:
        raise RuntimeError("Zone not found")
    return zones[0]["id"]

def get_record_id(session, zone_id, record_name):
    r = session.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        params={"type": "A", "name": record_name},
    )
    r.raise_for_status()
    records = r.json()["result"]
    if not records:
        return None
    return records[0]["id"]

def get_record(session, zone_id, record_name):
    r = session.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        params={"type": "A", "name": record_name},
    )
    r.raise_for_status()
    records = r.json()["result"]
    if not records:
        return None
    return records[0]


def update_record(session, zone_id, record_id, record_name, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    if record_id:
        url = f"{url}/{record_id}"
        method = session.put
    else:
        method = session.post
    r = method(
        url,
        json={"type": "A", "name": record_name, "content": ip, "ttl": 300},
    )
    r.raise_for_status()
    return r.json()

def get_datestr(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def heartbeat() -> bool:
    ''' Check if we need to send a 'still running' heartbeat '''
    now = time.time()
    lastsent = history.get('lastsent', 0)
    if lastsent + config.TIME_TO_NOTIFY < now:
        return True
    return False

def send_heartbeat() -> None:
    ''' Send the heartbeat '''
    last_hb = get_datestr(history.get("lastsent",0))
    rightnow = get_datestr(time.time())
    send_email(
        config.SENDFROM,
        config.SENDTO,
        notice=f"heartbeat - {rightnow}",
        msg=(
            f"DynamicDNS Updater Heartbeat:\n"
            f"- Last HB: {last_hb}\n"
            f"--\n{json.dumps(config.RECORDS,indent=2)}"
        )
    )

def send_update_notice(msg) -> None:
    ''' Email notifying of an update '''
    rightnow = get_datestr(time.time())
    send_email(
        config.SENDFROM,
        config.SENDTO,
        notice=f"DNS Update Notice - {rightnow}",
        msg=(
            f"DynamicDNS Updater Notice:\n\n"
            f"{msg}"
        )
    )

def dmesg(msg):
    print(f'D: {msg}')

def sanitize_record(record: str, domain: str) -> str:
    ''' Sanitize record name to ensure fully qualified '''
    if '.' in record and not record.endswith(domain):
        die(f'Invalid record definition for RECORD item: {domain=}, {record=}')
    if not '.' in record: record = f'{record}.{domain}'
    return record

        

def main() -> None:
    output_type = None
    output_msg = ''
    if heartbeat(): output_type = 'heartbeat'    
    ip = get_external_ip()
    
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {config.CF_API_TOKEN}", 
        "Content-Type": "application/json"
    })

    # Determine if any of the monitored domains need an IP update
    for item in config.RECORDS:
        domain = item['domain']
        record_name = sanitize_record(item['record'],domain)
        dmesg(f'{domain=}, {record_name=}')
        zone_id = get_zone_id(session, domain)
        record = get_record(session, zone_id, record_name)
        try: 
            record_ip = record['content']
            record_id = record['id']
        except: 
            record_ip = None
            record_id = None

        if not record_ip == ip:
            # Flag for update processing at the end
            output_type = 'update'
            output_msg += (
                f'- {domain=}\n'
                f'  - {record_ip=} / WAN_IP {ip}\n'
            )
            result = update_record(session, zone_id, record_id, record_name, ip)
            output_msg += (
                f'--\n{json.dumps(result,indent=2)}\n--\n\n'
            )

    # Handle output conditions on exit
    
    if output_type == 'heartbeat':
        send_heartbeat()

    if output_type == 'update':
        send_update_notice(output_msg)


''' Module Onload Operations '''

config = ConfigClass()
history = HistoryClass()
if __name__ == '__main__':
    main()
    exit(0)

