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
# Disabling warnings from urllib3 because I use a Mac and Apple mucks things up
#  by building with LibreSSH instead of OpenSSH...
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

ARGUMENTS = ['monitor','show-log']

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
        self.flush_data()
    
    def flush_data(self) -> None:
        try:
            with open(self.history_file,'w') as f:
                _ = json.dump(self.data, f)
        except Exception as e:
            die(
                f'Error while updating history file: {str(self.history_file)}'
                f'\n--\n{e}'
            )
    
    def log(self, msg: str) -> None:
        if (
            self.data.get('log',None) is None
            or not isinstance(self.data.get('log',None),dict)
        ):
            self.data['log'] = {}
        self.data['log'][time.time()] = msg
        self.flush_data()

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
    subject = f"[cfddns] {notice}"
    email_body = (
        f'To: {send_to}\n'
        f'From: {send_from}\n'
        f'Subject: {subject}\n'
        f'Content-Type: text/html; charset="utf-8"\n\n'
        f'<html><body>'
        f'<pre style="background-color:#EFEFEF; border:1px solid #999999; '
        f'border-radius:5px; color:#000000; padding:8px; font-size: 14px;">'
        f'<code style="white-space: pre;">{msg}</code></pre></body></html>'
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


def web_get(url: str, params: dict = {}) -> requests.Response:
    try:
        r = requests.get(url, params=params)
        r.raise_for_status()
        return r
    except Exception as e:
        history.log(f'GET {url} [{params}] failed - {e}')
        exit(1)


def get_external_ip() -> str:
    r = requests.get("https://api.ipify.org?format=json")
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
            f"--\n{json.dumps(config.RECORDS,indent=2)}\n--\n"
            f"Latest Logs:\n{show_log(reverse=True,limit=10)}"
        )
    )
    history.log(f'Sent heartbeat email to {config.SENDTO}')

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

def sanitize_record(record: str, domain: str) -> str:
    ''' Sanitize record name to ensure fully qualified '''
    if '.' in record and not record.endswith(domain):
        die(f'Invalid record definition for RECORD item: {domain=}, {record=}')
    if not '.' in record: record = f'{record}.{domain}'
    return record


def show_log(reverse = False,limit: int = None) -> str:
    ''' 
    Returns log message content as a str based on parameters as newline
    separated log messages
    '''
    logs = history.get('log',{})
    if not logs:
        return f'No logs...\n'

    log_index = list(logs.keys())

    if limit:
        # limit is always based around most-recent
        log_index.sort(reverse=True)
        log_index = log_index[0:limit]

    # Now apply output sort order
    log_index.sort(reverse=reverse)
    output = ''
    for index in log_index:
        timestamp = float(index)
        output += f'{get_datestr(timestamp)} - {logs[index]}\n'

    return output


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

        zone_id = get_zone_id(session, domain)
        record = get_record(session, zone_id, record_name)
        try: 
            record_ip = record['content']
            record_id = record['id']
        except: 
            record_ip = None
            record_id = None
            history.log(f'DNS entry missing for {domain=}, {record_name=}')

        if not record_ip == ip:
            # Flag for update processing at the end
            output_type = 'update'
            output_msg += (
                f'- {domain=}'
                f'  - {record_ip=} -> WAN_IP {ip}\n'
            )
            result = update_record(session, zone_id, record_id, record_name, ip)
            output_msg += (
                f'\nResponse Data:\n{json.dumps(result,indent=2)}\n\n'
            )
            history.log(f'Updated DNS entry for {record_name=} from {record_ip=} -> {ip}')

    # Handle output conditions on exit
    
    if output_type == 'heartbeat':
        send_heartbeat()

    if output_type == 'update':
        send_update_notice(output_msg)


''' Module Onload Operations '''
# Usage check section
def usage() -> None:
    script_name = os.path.basename(__file__)
    print(
        f'Usage error: {script_name} {{monitor|show-log [options]}}\n'
        f'\tmonitor - perform dynamic DNS update check\n'
        f'\tshow-log - show activity log\n'
        f'\t\toptions:   reverse - show logs newest to oldest\n'
        f'\t\t           limit:# - limit logs listed to # most recent\n'
        f'\t\texample:\n'
        f'\t\t         > {script_name} show-log reverse limit:10\n'
        f'\t\t           - Show 10 most recent logs newest-to-oldest'
    )
    exit(1)

if len(sys.argv) < 2: usage()
if not sys.argv[1].lower() in ARGUMENTS: usage()

config = ConfigClass()
history = HistoryClass()

if __name__ == '__main__':
    if sys.argv[1].lower() == 'monitor': 
        main()
        exit(0)
    
    if sys.argv[1].lower() == 'show-log':
        limit = None
        reverse = False    
        if 'reverse' in [x.lower() for x in sys.argv]:
            reverse = True
        for arg in sys.argv[2:]:
            if arg.startswith('limit:'):
                try:
                    limit = int(arg.split(':',1)[1])
                except:
                    usage()
        print(show_log(reverse=reverse,limit=limit))
        exit(0)

