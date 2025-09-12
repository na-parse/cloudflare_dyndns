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
{  
    "CF_API_TOKEN": <Cloudflare API Token with zone view-edit permissions>,
    "RECORDS": [
        {'domain': zone_name, 'record': hostname}, ...
    ],
    TIME_TO_NOTIFY: <int in seconds for heartbeat interval based on lastsent>,
    SENDFROM: <Email address to use as From:>,
    SENDTO: <Email address of recipient for updates/heartbeats
}
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
from enum import Enum, auto

HEARTBEAT_REQUIRED = False

### Allowed CLI Arguments
ALLOWED_CLI_ARGS = ['verbose','show']
APP_NAME = os.path.basename(__file__).replace('.py','')

### Defaults
DEFAULT_CONFIG_FILE  = Path(__file__).parent / '.config'
DEFAULT_HISTORY_FILE = Path(__file__).parent / '.history'
DEFAULT_LOG_FILE     = Path(__file__).parent / 'cfddns_activity.log'

### TODO: Config
FAILURES_BEFORE_ALERT = 3
DELAY_AFTER_ERROR = 60 * 60 # 1 Hour


### Utility definitions
def die(
    msg: str, 
    verbose: bool = True, 
    exit_code: int = 1, 
    cleanup = None
) -> None:
    '''
    Fatal Event Handler - Prints message to console and logs message
      to the event log.  Exits with specified (non-zero) exit code.
    If cleanup is specified and callable, it will be called before exting.
    '''
    # Try to log but don't raise an exception if something is wrong
    # with the logger
    try: log.fatal(f'{msg}')
    except: raise

    if verbose: print(f'[FATAL] Exiting: {msg}')
    if callable(cleanup): cleanup()

    if not isinstance(exit_code,int) or exit_code == 0:
        exit(7)
    exit(exit_code)

def dmesg(msg: str) -> None:
    ''' Debugging only - calls to dmesg should be removed before push '''
    print(f'D: {msg}')    

def get_datestr(timestamp: float) -> str:
    ''' Return a nicely formatted datestring for a given timestamp '''
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def sanitize_file_path(path_arg: Path, default_value: Path = None) -> Path:
    ''' 
    Santize and ensure path is a Path object, and handle default value
    assignment for method arguments.
    '''
    if path_arg is None and default_value is None:
        print(f'Unable to sanitize a None-type path value',file=sys.stderr)
        exit(2)
    return Path(path_arg or default_value)

def sanitize_record(record: str, domain: str) -> str:
    ''' Sanitize DNS record name to ensure fully qualified '''
    if '.' in record and not record.endswith(domain):
        print(
            f'Invalid record definition for RECORD item: {domain=}, {record=}',
            file=sys.stderr
            )
    if not '.' in record: 
        record = f'{record}.{domain}'
    return record

def check_for_delay() -> bool:
    '''
    Checks if a delay has been set in response to a previous runtime error.
    Clears any existing delay timer for an expired timer was set.

    Returns:
        True - Delay timer exists and has not expired
        False - Delay timer does not exist or has expired
    '''
    delay_nextrun = history.get('delay_nextrun',None)
    if delay_nextrun and delay_nextrun > time.time():
        # Delay is set and has not expired
        return True
    elif delay_nextrun and delay_nextrun < time.time():
        # Delay is set and expired
        log.debug(f'Delay timner for {get_datestr(delay_nextrun)} has expired.')
        history.update('delay_nextrun',0)
    # No delay applicable
    return False




### cfddns Operational Objects
class ConfigClass:
    '''
    Configuration Handler
    Reads in the configuration file and sets class attributes per
    configuration file's JSON data.

    Arguments:
        config_file (opt) - Uses DEFAULT_CONFIG_FILE path by default
    
    config_file JSON Expected Values:
        CF_API_TOKEN: str - Cloudflare API Token with zone view-edit perms
        RECORDS: list - dict objects {domain: zone, record_name: host}
        TIME_TO_NOTIFY: int - Seconds from lastsent timestamp for hb email
        SENDTO: str - Email address recipient for updates/heartbeat emails
        SENDFROM: str - Email address to use as originator for emails
    '''
    def __init__(self, config_file: Path = None):
        config_file = sanitize_file_path(config_file, DEFAULT_CONFIG_FILE)
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
    def __str__(self):
        out = (
            f'Current Configuration Values:  \n'
            f'   CF_API_TOKEN={self.CF_API_TOKEN}\n'
            f'   RECORDS: \n'
        )
        for item in self.RECORDS:
            out += (
                f'        domain={item["domain"]} - record={item["record"]}\n'
            )
        out += (
            f'    TIME_TO_NOTIFY={self.TIME_TO_NOTIFY}\n'
            f'    SENDTO={self.SENDTO}\n'
            f'    SENDFROM={self.SENDFROM}'
        )
        return out


class HistoryClass:
    '''
    Tracking object for operation behaviors and internal logic control.
    Currently only being used to track when last email was sent for 
    heartbeat purposes.
    
    TODO: Track configured DNS entries so we can tell when things are
          removed or added.
    '''
    def __init__(self, history_file: Path = None):
        self.run_id = time.time()

        self.history_file = sanitize_file_path(
            history_file, DEFAULT_HISTORY_FILE
        )
        self.data = self._load_history()

    def get(self,data_key, default_value: Any = None) -> Any:
        return self.data.get(data_key,default_value)

    def update(self,data_key,data_value) -> None:
        self.data[data_key] = data_value
        self._flush_data()
    
    def add_failure(self, delay: int = None) -> int:
        ''' 
        Track current run as a failure and return current failure count as int
        '''
        # Setup the next-run delay threshold for an error
        delay = delay or DELAY_AFTER_ERROR
        delay_until = time.time() + delay
        failures = self.data.get('failures',{})
        failures[self.run_id] = True
        self.update('failures',failures)
        self.update('delay_nextrun',delay_until)
        log.info(f'Failure detected - delaying next run until {get_datestr(delay_until)}')
        return len(failures)
    
    def clear_failures(self) -> None:
        '''
        Clear all failure events and details
        '''
        self.update('failures',{})
        self.update('failure_sent',0)

    def _flush_data(self) -> None:
        try:
            with open(self.history_file,'w') as f:
                _ = json.dump(self.data, f)
        except Exception as e:
            die(
                f'Error while updating history file: {str(self.history_file)}'
                f'\n--\n{e}'
            )

    def _load_history(self):
        data = {}
        if self.history_file.exists():
            try:
                with open(self.history_file,'r') as f:
                    data = json.load(f)  
            except Exception as e:
                print(f'Issue with history file, resetting...')
                os.remove(self.history_file)
        return data


class LogClass:
    '''
    Could I use the python logging module?  Yes.  Did I?  No.
    This is actually because I already wrote a json logging thing but decided
    to roll it back to a flat log file.  One day I'll start using logging.
    But not today.

    Methods:
        .info(msg)  - Logs message to log file (print if verbose)
        .debug(msg) - Prints and logs msg only if verbose)
    '''
    def __init__(self, log_file: Path = None, verbose: bool = False):
        self.log_file = sanitize_file_path(
            log_file, DEFAULT_LOG_FILE
        )
        self.verbose = verbose
        self.app_name = APP_NAME

    def fatal(self, msg: str) -> None:
        logmsg = self._mk_logmsg(msg, 'FATAL')
        if self.verbose: print(logmsg)
        self._flush(logmsg)

    def info(self, msg: str) -> None:
        logmsg = self._mk_logmsg(msg, 'INFO')
        if self.verbose: print(logmsg)
        self._flush(logmsg)

    def debug(self, msg: str) -> None:
        if not self.verbose: return
        logmsg = self._mk_logmsg(msg, 'DEBUG')
        print(logmsg)
        self._flush(logmsg)
    
    def show(self, reverse=False, limit=None) -> str:
        '''
        Returns log messages from the log file based on args.
        Provides recent log messages for the heartbeat activity report.
        '''
        try:
            with open(self.log_file,'r') as f:
                lines = [ l.strip() for l in f.readlines() ]
        except FileNotFoundError:
            lines = []
        
        if reverse: lines.reverse()
        limit = limit or len(lines)
        return "\n".join(lines[0:limit])
    
    def _mk_logmsg(self, msg: str, level: str = "INFO") -> str:
        return (
            f'[{get_datestr(time.time())}] {self.app_name} - '
            f'{level} - {msg}'
        )
    
    def _flush(self, logmsg) -> None:
        try:
            with open(self.log_file,'a') as f:
                print(logmsg,file=f)
        except Exception as e:
            # Print an error message but let the monitor keep running
            print(
                f'Error while writing to log file: {e}',
                file=sys.stderr
            )


##### API Endpoint Management

class HttpMethod(Enum):
    GET = auto()
    POST = auto()
    PUT = auto()

def api_request(
    method: HttpMethod,
    url: str,
    session: requests.Session = None,
    params: dict = None,
    json: dict = None
) -> requests.Response:
    ''' 
    Wrapper for API calls to centralize exception and error handling.
    cfddns behavior is to log the error/issue in history log and
    exit in a non-zero status without any console output.
    '''
    global HEARTBEAT_REQUIRED
    # Setup the headers to explicitly state JSON
    if not session: session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    if method == HttpMethod.GET: apifunc = session.get
    if method == HttpMethod.POST: apifunc = session.post
    if method == HttpMethod.PUT: apifunc = session.put

    try:
        log.debug(
            f'Making API Request - {method.name} - {url} {params=} {json=}'
        )
        response = apifunc(url, params=params, json=json)
        
        # Check for random internal server errors
        response.raise_for_status()

        return response
    except Exception as e:
        '''
        API busy or temporarily unavailable.  Handle silently and try again
        later until consecutive errors exceed the threshold.
        '''
        failure_count = history.add_failure()

        # Identify if we need to send a cleanup method to die()
        cleanup_method = None
        if HEARTBEAT_REQUIRED:
            log.debug(f'{HEARTBEAT_REQUIRED=}, Setting send_heartbeat for cleanup')
            cleanup_method = send_heartbeat
        if (
            failure_count >= FAILURES_BEFORE_ALERT
            and not history.get('failure_sent',0) 
        ):
            log.debug(f'{failure_count=}, {FAILURES_BEFORE_ALERT=}, Setting send_failure_notification for cleanup')
            cleanup_method = send_failure_notification
        
        die(
            f'API_REQUEST Failed [{failure_count}] {e}',
            exit_code=99,
            verbose=False,
            cleanup=cleanup_method
        )


def get_external_ip() -> str:
    r = api_request(
        HttpMethod.GET, "https://api.ipify.org", params={'format': 'json'}
    )
    return r.json()["ip"]

def get_zone_id(session, zone_name):
    r = api_request(
        HttpMethod.GET,
        "https://api.cloudflaxre.com/client/v4/zones",
        session=session,
        params={"name": zone_name},
    )
    zones = r.json()["result"]
    if not zones:
        die(f'Zone not found/authorized for this account: {zone_name}')
    return zones[0]["id"]

def get_record_id(session, zone_id, record_name):
    r = api_request(
        HttpMethod.GET,
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        session=session,
        params={"type": "A", "name": record_name}
    )
    records = r.json()["result"]
    if not records:
        return None
    return records[0]["id"]

def get_record(session, zone_id, record_name):
    r = api_request(
        HttpMethod.GET,
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        session=session,
        params={"type": "A", "name": record_name},
    )
    records = r.json()["result"]
    if not records:
        return None
    return records[0]

def update_record(session, zone_id, record_id, record_name, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    if record_id:
        url = f"{url}/{record_id}"
        method = HttpMethod.PUT
    else:
        method = HttpMethod.POST
    r = api_request(
        method,
        url,
        session=session,
        json={"type": "A", "name": record_name, "content": ip, "ttl": 300},
    )
    return r.json()


### Email Handling
def send_email(send_from: str, send_to: str, notice: str, msg: str):
    subject = f"[{APP_NAME}] {notice}"
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


### Heartbeat for Active Monitoring Confirmation
def heartbeat() -> bool:
    ''' 
    Check if a heartbeat is necessary based on the duration since the last
    user notification email was sent. 
    '''
    now = time.time()
    lastsent = history.get('lastsent', 0)
    if lastsent + config.TIME_TO_NOTIFY < now:
        log.debug(f'Heartbeat required - Last Sent {get_datestr(lastsent)}')
        return True
    return False


### Notification Senders

def send_heartbeat() -> None:
    ''' Send a notification heartbeat email '''
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
            f"Latest Logs:\n{log.show(reverse=True,limit=10)}"
        )
    )
    log.info(f'Sent heartbeat email to {config.SENDTO}')

def send_failure_notification() -> None:
    ''' Send notification of excessive API failures '''
    failure_sent = history.get('failure_sent',0)
    failure_count = len(history.get('failures',[]))
    if failure_sent > 0: 
        # Failure has already been sent, exit
        exit(1)
    send_email(
        config.SENDFROM,
        config.SENDTO,
        notice=f'Excessive API Failures Updating DNS',
        msg=(
            f"Experiencing excessive API failures - {failure_count}\n"
            f"--\n{json.dumps(config.RECORDS,indent=2)}\n--\n"
            f"Latest Logs:\n{log.show(reverse=True,limit=20)}"
        )
    )
    history.update('failure_sent',time.time())
    log.info(f'Sent excessive failures email to {config.SENDTO}')
    exit(1)


def send_update_notice(msg) -> None:
    ''' Send a notification of update email '''
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
    log.info(f'Sent DNS update email to {config.SENDTO}')


### Main Monitoring Pass Function
def ddns_monitor() -> None:
    '''
    Primary Dyanmic DNS Monitor and Update method
    '''
    global HEARTBEAT_REQUIRED
    if check_for_delay():
        log.debug(
            f'Exiting without running due to existing delay: '
            f'nextrun="{get_datestr(history.get("delay_nextrun"))}"'
        )
        exit(0)
    
    output_type = None
    output_msg = ''

    if heartbeat(): 
        output_type = 'heartbeat'
        HEARTBEAT_REQUIRED = True
    
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
            log.info(f'DNS entry missing for {domain=}, {record_name=}')

        if not record_ip == ip:
            # Flag for update processing at the end
            output_type = 'update'
            action_type = "Updated" if record_ip else "New Record"
            output_msg += (
                f'{action_type}: {record_name} (zone: {domain}) '
                f'{record_ip} -> WAN_IP {ip}\n'
            )
            result = update_record(session, zone_id, record_id, record_name, ip)
            output_msg += (
                f'Response Data:\n{json.dumps(result,indent=2)}\n\n'
            )
            log.info(f'Updated DNS entry "{record_name}" from {record_ip} -> {ip}')

    # Handle output conditions on exit
    if output_type == 'heartbeat':
        send_heartbeat()

    if output_type == 'update':
        send_update_notice(output_msg)

    if output_type is None:
        log.debug(f'No updates performed.  Normal exit.')

    # Normal exit - Clean up any previous API failures
    history.clear_failures()



### Script On-Load Execution

# Define module level operations class instances
log = LogClass()
config = ConfigClass()
history = HistoryClass()


# Usage check section
def usage() -> None:
    script_name = os.path.basename(__file__)
    print(
        f'Usage error: {script_name} {{verbose|show}}\n'
        f'    verbose -  log debugging messages and print to console\n'
        f'    show    -  Show the current configuration values\n'
    )
    exit(1)

if len(sys.argv) > 1:
    if not sys.argv[1].lower() in ALLOWED_CLI_ARGS: usage()
    if 'verbose' in sys.argv[1].lower():
        log.verbose = True
        log.debug(f'Enabling verbose output')
    if 'show' in sys.argv[1].lower():
        print(config)
        exit(0)

if __name__ == '__main__':
    log.debug(f'Starting cloudflare_dyndns monitoring and update run')    
    ddns_monitor()
    exit(0)
