#!/usr/local/bin/python3

# HTTP requests
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse

# DNS stuff
import socket
import re
import dns.resolver

# AWS
import boto3

# Standard library
import json
import sys
import time
import os
import glob
import configparser
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# SSL stuff
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import argparse

# Globals
stats = {
  'http_requests': 0,
  'https_requests': 0,
  'dns_lookups': 0,
  'dns_cached': 0,
  'wait_time': 0,
  'aws_load_time': 0,
  'start_time': time.time()
}

# Progress meter. Count the number of records during loading. Show percentage that are certain.

args = None

safedomains = []
safeips = []
safestrings = []
safeorganizations = []
safehostingproviders = []
seedurls = {}

records={}

timeoutIPs = []
timeoutDomains = []

custom_dns_servers = []  # Custom DNS servers for resolution, empty means use system defaults

def parse_ini_config(section):
  """Parse INI config section and return argv list."""
  argv = []

  # Debug mode
  if section.getboolean('debug', False):
    argv.append('--debug')

  # Score threshold
  if 'score' in section:
    argv.extend(['--score', section['score']])

  # Input file
  if 'input' in section:
    argv.extend(['--input', section['input']])

  # Compare to file
  if 'compare-to' in section:
    argv.extend(['--compare-to', section['compare-to']])

  # AWS Route53 mode
  if section.getboolean('aws-route53', False):
    argv.append('--aws-route53')

  # AWS profile
  if 'aws-profile' in section:
    argv.extend(['--aws-profile', section['aws-profile']])

  # AWS region
  if 'aws-region' in section:
    argv.extend(['--aws-region', section['aws-region']])

  # DNS servers
  if 'dns-servers' in section:
    argv.extend(['--dns-servers', section['dns-servers']])

  return argv

def parse_json_config(config_dict):
  """Parse JSON config dict and return argv list."""
  argv = []

  # Debug mode
  if config_dict.get('debug', False):
    argv.append('--debug')

  # Score threshold
  if 'score' in config_dict:
    argv.extend(['--score', str(config_dict['score'])])

  # Input file
  if 'input' in config_dict:
    argv.extend(['--input', config_dict['input']])

  # Compare to file
  if 'compare-to' in config_dict:
    argv.extend(['--compare-to', config_dict['compare-to']])

  # AWS Route53 mode
  if config_dict.get('aws-route53', False):
    argv.append('--aws-route53')

  # AWS profile
  if 'aws-profile' in config_dict:
    argv.extend(['--aws-profile', config_dict['aws-profile']])

  # AWS region
  if 'aws-region' in config_dict:
    argv.extend(['--aws-region', config_dict['aws-region']])

  # DNS servers
  if 'dns-servers' in config_dict:
    argv.extend(['--dns-servers', config_dict['dns-servers']])

  return argv

def load_config_file(config_file):
  """Load configuration from a file and convert to command-line arguments.
  Returns a list of arguments that can be parsed by argparse.
  Supports both INI format (.conf, .ini, .cfg) and JSON format (.json).
  """
  argv = []

  if not os.path.exists(config_file):
    print(f"WARNING: Config file not found: {config_file}")
    return argv

  try:
    # Try INI format
    if config_file.endswith(('.conf', '.ini', '.cfg')):
      config = configparser.ConfigParser()
      config.read(config_file)

      if 'dangling-dns' in config:
        argv = parse_ini_config(config['dangling-dns'])

    # Try JSON format
    elif config_file.endswith('.json'):
      with open(config_file, 'r') as f:
        config_data = json.load(f)

      # Ensure the config is under a 'dangling-dns' key or is a flat dict
      if 'dangling-dns' in config_data:
        config_dict = config_data['dangling-dns']
      else:
        config_dict = config_data

      argv = parse_json_config(config_dict)

  except Exception as e:
    print(f"ERROR: Failed to parse config file {config_file}: {e}")
    sys.exit(1)

  return argv

def find_default_config_file():
  """Search for default config file locations."""
  default_paths = [
    os.path.expanduser('./dangling-dns.conf'),
    os.path.expanduser('~/.dangling-dns.conf'),
  ]
  for path in default_paths:
    if os.path.exists(path):
      return path
  return None

def parseOptions():
  # Potential options:
  # -d --debug debug mode
  # -s --score <number> The maximum score to include in the output. Anything higher than this will not be printed.

  # -i input domains file

  parser = argparse.ArgumentParser(description='Dangling DNS evaluator.')

  # Config file (parse this first to set defaults)
  parser.add_argument('--config', type=str, default=None,
                      help='Path to configuration file (INI or JSON format).')

  # Debug
  parser.add_argument('-d', '--debug', action='store_true',
                      help='Turn debug mode on.')

  # Score
  parser.add_argument('-s', '--score', type=int, default=90,
                      help='The threshold for scores to include in the output. Anything higher will not be included. Default: 90')

  # Input records file
  parser.add_argument('-i', '--input', type=str, default='./records.txt',
                      help='An input file full of DNS records. Default: ./records.txt')

  # Compare to previous records file
  parser.add_argument('--compare-to', type=str, default=None,
                      help='Compare the current records to a previous records JSON file and highlight risky differences.')

  # AWS Route53 integration
  parser.add_argument('--aws-route53', action='store_true',
                      help='Fetch DNS records from AWS Route53 instead of using a local file.')
  parser.add_argument('--aws-profile', type=str, default=None,
                      help='AWS profile name to use for Route53 access.')
  parser.add_argument('--aws-region', type=str, default='us-east-1',
                      help='AWS region to use. Default: us-east-1')

  # Custom DNS servers
  parser.add_argument('--dns-servers', type=str, default=None,
                      help='Comma-separated list of custom DNS servers (e.g., 8.8.8.8,1.1.1.1). Default: system resolvers.')

  # First parse to get config file path (if specified)
  args_temp = parser.parse_args()

  # Load config file if specified or check for default locations
  config_argv = []
  config_file = args_temp.config or find_default_config_file()
  if config_file:
    config_argv = load_config_file(config_file)

  # Merge config file arguments with command-line arguments (CLI takes precedence)
  merged_argv = config_argv + sys.argv[1:]

  # Re-parse with merged arguments
  global args
  args = parser.parse_args(merged_argv)

  # Now log the config file load (after args is set)
  if config_file and config_argv:
    log(f"Loaded config from {config_file}", "debug")

  log("Parsed args:", "debug")
  log(f"Debug: {args.debug}", "debug")
  log(f"Score: {args.score}", "debug")
  if args.aws_route53:
    log("AWS Route53 mode enabled", "debug")
    log(f"AWS Profile: {args.aws_profile if args.aws_profile else 'default'}", "debug")
  else:
    log(f"Input file: {args.input}", "debug")

  global custom_dns_servers
  if args.dns_servers:
    custom_dns_servers = [s.strip() for s in args.dns_servers.split(',')]
    log(f"Custom DNS servers configured: {custom_dns_servers}", "debug")
  else:
    log("Using system default DNS resolvers", "debug")

def compare_records(current_records, previous_records):
  risky_diffs = []
  for record in current_records:
    # Skip records with underscores as they are always safe
    if '_' in record:
      continue
    if record in previous_records:
      prev_score = previous_records[record].get('Score', 0)
      curr_score = current_records[record].get('Score', 0)
      # Highlight if a record has become unsafe or dropped significantly
      if prev_score > 10 and curr_score <= 10:
        causes = current_records[record].get('causes', [])
        risky_diffs.append((record, prev_score, curr_score, 'Became unsafe', causes))
      elif curr_score < prev_score and curr_score <= 10:
        causes = current_records[record].get('causes', [])
        risky_diffs.append((record, prev_score, curr_score, 'Score dropped to risky', causes))
    else:
      # New record, could be risky if score is low
      curr_score = current_records[record].get('Score', 0)
      if curr_score <= 10:
        causes = current_records[record].get('causes', [])
        risky_diffs.append((record, None, curr_score, 'New risky record', causes))
  for record in previous_records:
    # Skip records with underscores as they are always safe
    if '_' in record:
      continue
    if record not in current_records:
      prev_score = previous_records[record].get('Score', 0)
      if prev_score > 10:
        risky_diffs.append((record, prev_score, None, 'Record missing (was safe)', []))
  if risky_diffs:
    print('== DIFFERENCES FOUND: ==')
    for rec, prev, curr, reason, causes in risky_diffs:
      causes_str = ', '.join(causes) if causes else 'Unknown'
      print(f"- {rec}: {reason} (Previous: {prev}, Current: {curr}) Reasons: {causes_str}")
  else:
    print('\nNo risky differences found between current and previous records.')

def loadSafeDomains():
  # Load safedomains from safedomains.txt
  f = open(f"safedomains.txt")
  lines = f.readlines()
  for line in lines:
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove trailing dots
    line = re.sub(r"\.$", "", line)
    # Remove whitespace
    line = re.sub("[ \n]", "", line)
    if line != "":
      log(f"Adding \"{line}\" to safedomains", "debug")
      safedomains.append(line)
  #  else:
  #    log(f"Not adding \"{line}\" to safedomains", "debug")
  f.close()

def loadSafeIPs():
  # Load safeips from safeips.txt
  f = open(f"safeips.txt")
  lines = f.readlines()
  for line in lines:
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove whitespace
    line = re.sub("[ \n]", "", line)
    if line != "":
      log(f"Adding \"{line}\" to safeips", "debug")
      safeips.append(line)
  #  else:
  #    log(f"Not adding \"{line}\" to safeips", "debug")
  f.close()

def loadSafeStrings():
  # Load safestrings from safestrings.txt
  f = open(f"safestrings.txt")
  lines = f.readlines()
  for line in lines:
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove newlines
    line = re.sub("\n", "", line)
    # Remove trailing whitespace
    line = re.sub(" *$", "", line)
    # Remove leading whitespace
    line = re.sub("^ *", "", line)
    if line != "":
      log(f"Adding \"{line}\" to safestrings", "debug")
      safestrings.append(line)
    else:
      log(f"Not adding \"{line}\" to safestrings", "debug")
  f.close()

def loadSafeOrganizations():
  # Load safeorganizations from safeorganizations.txt
  f = open(f"safeorganizations.txt")
  lines = f.readlines()
  for line in lines:
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove newlines
    line = re.sub("\n", "", line)
    # Remove trailing whitespace
    line = re.sub(" *$", "", line)
    # Remove leading whitespace
    line = re.sub("^ *", "", line)
    if line != "":
      log(f"Adding \"{line}\" to safeorganizations", "debug")
      safeorganizations.append(line)
  f.close()

def loadSafeHostingProviders():
  # Load safehostingproviders from safehostingproviders.txt
  # Format: provider_name:IP_prefix
  f = open(f"safehostingproviders.txt")
  lines = f.readlines()
  for line in lines:
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove newlines and whitespace
    line = re.sub("[\n ]", "", line)
    if line != "":
      log(f"Adding \"{line}\" to safehostingproviders", "debug")
      safehostingproviders.append(line)
  f.close()

def loadSeedURLs():
  # Some sites don't have anything identifiable on the homepage but do on other pages. This list helps us find them.
  f = open(f"seedurls.txt")
  lines = f.readlines()
  for line in lines:
    origLine = line
    # Remove comments
    line = re.sub("#.*", "", line)
    # Remove newlines and whitespace
    line = re.sub("[ \n]", "", line)
    # Remove newlines from original line because it messes up debug output
    origLine = re.sub("\n", "", origLine)
    if line != "":
      domain = urlparse(line).netloc
      log(f"Adding {domain}: {line} to seedurls", "debug")
      seedurls[domain] = line
    else:
      log(f"Not adding anything from {origLine} to seedurls", "debug")

def load_zone_records(zone_id, zone_name, route53_client):
  """Load all DNS records for a single hosted zone."""
  try:
    zone_records = {}
    record_paginator = route53_client.get_paginator('list_resource_record_sets')
    for record_page in record_paginator.paginate(HostedZoneId=zone_id):
      for record_set in record_page['ResourceRecordSets']:
        if record_set['Type'] in ['A', 'CNAME', 'NS']:
          record_name = record_set['Name'].rstrip('.')
          resource_records = [{'Value': rr['Value']} for rr in record_set.get('ResourceRecords', [])]
          zone_records[record_name] = {
            'Name': record_name,
            'Type': record_set['Type'],
            'ResourceRecords': sorted(resource_records, key=lambda d: d['Value']),
            'Score': 0
          }
    log(f"Loaded {len(zone_records)} records from zone {zone_name}", "debug")
    return zone_records
  except Exception as e:
    log(f"Error loading records from zone {zone_name}: {e}", "error")
    return {}

def loadDNSRecordsFromAWS():
  aws_start_time = time.time()
  log(f"Loading DNS records from AWS Route53.", "info")
  try:
    session = boto3.Session(profile_name=args.aws_profile, region_name=args.aws_region)
    route53 = session.client('route53')

    # Get list of hosted zones
    paginator = route53.get_paginator('list_hosted_zones')
    zones = []
    for page in paginator.paginate():
      for zone in page['HostedZones']:
        zone_id = zone['Id']
        zone_name = zone['Name'].rstrip('.')
        zones.append((zone_id, zone_name))

    log(f"Found {len(zones)} hosted zones to process", "debug")

    # Load records from all zones in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
      futures = {executor.submit(load_zone_records, zone_id, zone_name, route53): (zone_id, zone_name)
                 for zone_id, zone_name in zones}

      for future in as_completed(futures):
        zone_records = future.result()
        # Merge zone records into main records dict
        records.update(zone_records)

    stats['aws_load_time'] = time.time() - aws_start_time
    log(f"Finished loading {len(records)} records from AWS Route53 in {stats['aws_load_time']:.2f}s.", "debug")
    return True
  except (boto3.exceptions.Boto3Error, Exception) as e:
    stats['aws_load_time'] = time.time() - aws_start_time
    error_msg = str(e)
    # Check if this is a credential-related error
    if any(keyword in error_msg for keyword in ['InvalidClientTokenId', 'SignatureDoesNotMatch', 'NotAuthorizedToOperateOnLambdaFunction', 'UnrecognizedClientException', 'AccessDenied']):
      log(f"ERROR: Invalid AWS credentials. Please check your AWS profile '{args.aws_profile}' and region '{args.aws_region}'.", "error")
      log(f"Details: {error_msg}", "error")
      sys.exit(1)
    else:
      log(f"ERROR: Failed to load DNS records from AWS Route53: {error_msg}", "error")
      log(f"Please verify your AWS configuration and try again.", "error")
      sys.exit(1)

def loadDNSRecords():
  if args.aws_route53:
    return loadDNSRecordsFromAWS()

  log(f"Loading DNS records from file.", "debug")
  f = open(args.input)
  loadedrecords = json.load(f)
  for record in loadedrecords:
    if(record['Type'] == 'A' or record['Type'] == 'CNAME' or record['Type'] == 'NS'):
      # Strip off trailing dots as we go.
      if(record['Name'][-1] == '.'):
        record['Name'] = record['Name'][:-1]
      if('ResourceRecords' in record):
        record['ResourceRecords'] = sorted(record['ResourceRecords'], key=lambda d: d['Value']) # Sort these so that we can compare them day to day.
      records[record['Name']] = record
      records[record['Name']]['Score'] = 0

  del loadedrecords
  f.close()
  log(f"Finished loading records from file.", "debug")
  return True

def log(message, level):
  if(args.debug == False and level == "debug"):
    pass
  else:
    print(f"{datetime.now()} [{level.upper()}] {message}")

def find_most_recent_records_file():
  """Find the most recent records_YYYY-MM-DD.json file in the current directory.
  Returns the filename if found, None otherwise."""
  try:
    # Match the pattern records_YYYY-MM-DD.json
    pattern = "records_????-??-??.json"
    matching_files = glob.glob(pattern)

    if not matching_files:
      log("No records files matching pattern 'records_YYYY-MM-DD.json' found", "error")
      return None

    # Sort by modification time, newest first
    matching_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    most_recent = matching_files[0]
    log(f"Found most recent records file: {most_recent}", "debug")
    return most_recent
  except Exception as e:
    log(f"Error finding most recent records file: {e}", "error")
    return None

def retrySession(retries, session=None, backoff_factor=0.3):
  session = session or requests.Session()
  retry = Retry(
    total=retries,
    read=retries,
    connect=retries,
    backoff_factor=backoff_factor,
    allowed_methods=False,
  )
  adapter = HTTPAdapter(max_retries=retry)
  session.mount('http://', adapter)
  session.mount('https://', adapter)
  return session

def query_ns(nameserver, hostname, record_type):
  resolver = dns.resolver.Resolver()
  log(f"Querying NS {nameserver} for {hostname} {record_type}", "debug")
  resolver.nameservers = [nameserver]

  return resolver.resolve(qname = hostname, rdtype = record_type)

def get_resolver_with_custom_servers():
  """Get a DNS resolver configured with custom servers if provided, otherwise use system defaults."""
  resolver = dns.resolver.Resolver()
  if custom_dns_servers:
    resolver.nameservers = custom_dns_servers
    log(f"Using custom DNS servers: {custom_dns_servers}", "debug")
  return resolver

def get_authoritative_ns_records(hostname):
  """Query authoritative nameservers to get the true NS records for a domain.
  Returns a sorted list of authoritative NS server names, or empty list on failure."""
  try:
    # Use resolver with custom servers if configured, otherwise system defaults
    resolver = get_resolver_with_custom_servers()
    resolver.use_edns(0, dns.flags.DO, 1200)

    # Query for NS records - this will follow referrals to authoritative nameservers
    ns_answer = resolver.resolve(hostname, 'NS')
    authoritative_ns = sorted([str(rr).rstrip('.') for rr in ns_answer])

    log(f"Authoritative NS records for {hostname}: {authoritative_ns}", "debug")
    return authoritative_ns
  except Exception as e:
    log(f"Failed to query authoritative NS records for {hostname}: {e}", "debug")
    return []

def validate_ns_records(record, route53_ns_list):
  """Compare Route53 NS records against authoritative nameservers.
  Returns (has_mismatch, mismatched_servers, authoritative_ns) tuple."""
  # Extract nameserver names from Route53 records (strip trailing dots)
  route53_ns = sorted([ns.rstrip('.') for ns in route53_ns_list])

  # Get authoritative NS records
  authoritative_ns = get_authoritative_ns_records(record)

  if not authoritative_ns:
    log(f"Could not retrieve authoritative NS records for {record}, skipping validation", "debug")
    return (False, [], [])

  # Compare the two lists
  route53_set = set(route53_ns)
  authoritative_set = set(authoritative_ns)

  # Find nameservers in Route53 that aren't authoritative
  stale_ns = route53_set - authoritative_set
  # Find nameservers that are authoritative but missing from Route53
  missing_ns = authoritative_set - route53_set

  has_mismatch = len(stale_ns) > 0 or len(missing_ns) > 0

  if has_mismatch:
    if stale_ns:
      log(f"Stale NS records in Route53 for {record}: {stale_ns}", "warning")
    if missing_ns:
      log(f"Missing authoritative NS records in Route53 for {record}: {missing_ns}", "warning")

  return (has_mismatch, list(stale_ns), authoritative_ns)


def get_ipv4_by_hostname(hostname):

  if(hostname not in records):
    records[hostname] = {}
    records[hostname]['Score'] = 0
    log(f"Added new record for hostname {hostname}", "debug")

  if('ips' in records[hostname]):
    stats['dns_cached'] += 1
    return records[hostname]['ips']

  stats['dns_lookups'] += 1
  ips = []
  log(f"Resolving DNS for {hostname}", "debug")
  try:
    for i in socket.getaddrinfo(hostname, 0):
      if( i[0] is socket.AddressFamily.AF_INET and i[1] is socket.SocketKind.SOCK_STREAM):
        ips.append(i[4][0])
    records[hostname]['ips'] = sorted(ips)
    return sorted(ips)
  except Exception as e:
    if(e is socket.gaierror):
      log(f"DNS failed to resolve for {hostname}.", "debug")
    else:
      log(f"DNS failed to resolve for {hostname} {e}.", "debug")
    log(f"Adding IP list for {hostname} to {ips}", "debug")
    records[hostname]['ips'] = ips
    records[hostname]['TYPE'] = 'A' # It could actually be a CNAME but I don't think it matters because it's not ours. To be added here it's a discovered record.
    return ips

def getHttp(url):
  if(url[:5] == 'https'):
    stats['https_requests'] += 1
  else:
    stats['http_requests'] += 1
  session = retrySession(retries=0)
  # Possible errors:
  #   ReadTimeout
  #   ConnectTimeout
  #   Timeout
  #   ConnectionError
  try:
    log(f"Requesting {url}", "debug")
    start_time = time.time()
    response = session.get(url, timeout=3, allow_redirects=False)
    stats['wait_time'] += (time.time() - start_time)
    if(time.time() - start_time > 1):
      log(f"Slow response from {url}: {time.time() - start_time}", "debug")
    return response, None
  except requests.exceptions.SSLError as e:
    log(f"SSL error: {e} caused by {url}", "debug")
    return None, e
  except Exception as e:
    stats['wait_time'] += (time.time() - start_time)
    log(f"HTTP error: {e} caused by {url}", "debug")
    if(time.time() - start_time > 3):
      domain = urlparse(url).netloc
      ips = get_ipv4_by_hostname(domain)
      for ip in ips:
        if(ip in timeoutIPs):
          log(f"IP {ip} already in timeoutIPs from {domain}.", "debug")
        else:
          log(f"Adding IP {ip} to timeoutIPs from {domain}.", "debug")
          timeoutIPs.append(ip)
      log(f"Slow response from {url}: {time.time() - start_time}. Adding {ips} to timeoutIPs", "debug")
    return None, e

def follow_redirects(record, response, url):
    changed = 0
    redirectchain = 0
    while(response is not None and 'location' in response.headers and redirectchain < 10):
        # If the redirect target is on the safe list, add 100.
        domain = urlparse(response.headers['location']).netloc
        if(domain in safedomains):
            log(f"Raising score for redirect to safedomain {response.headers['location']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
            adjust_score(record, 100, "Redirect to safedomain")
            changed += 1
            redirectchain += 5 # Silly hack to prevent infinite loop here.
            break
        else:
            # If this is a path, add the domain and protocol. If this has no protocol, add one.
            log(f"Following redirect from {url} to {response.headers['location']}", "debug")
            redirectchain += 1
            newurl = response.headers['location']
            if newurl.startswith('//'):
                newurl = f"https:{newurl}"
                log(f"Updated redirect from {response.headers['location']} to {newurl}", "debug")
            elif newurl.startswith('/'):
                newurl = f"https://{urlparse(url).netloc}{newurl}"
                log(f"Updated redirect from {response.headers['location']} to {newurl}", "debug")
            url = newurl
            response, _ = getHttp(url)
    # If we exit due to too many redirects, do nothing here (handled in analyse_http)
    return changed

def get_tls_names(domain):
  try:
    certificate: bytes = ssl.get_server_certificate((domain, 443)).encode('utf-8')
    loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
    common_name = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    log(common_name, "debug")
    # classes must be subtype of:
    #   https://cryptography.io/en/latest/x509/reference/#cryptography.x509.ExtensionType
    san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_dns_names = san.value.get_values_for_type(x509.DNSName)
  except Exception as e:
    log(f"Error getting SAN DNS names for {domain}: {e}", "debug")
    san_dns_names = []
  return san_dns_names

def get_certificate_organization(domain):
  try:
    certificate: bytes = ssl.get_server_certificate((domain, 443)).encode('utf-8')
    loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
    org_attrs = loaded_cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
    if org_attrs:
      organization = org_attrs[0].value
      log(f"Certificate organization for {domain}: {organization}", "debug")
      return organization
  except Exception as e:
    log(f"Error getting certificate organization for {domain}: {e}", "debug")
  return None

def check_ip_hosting_provider(ip):
  """Check if IP address matches any known hosting providers.
  Returns tuple (matched, provider_name) or (False, None)."""
  for provider_entry in safehostingproviders:
    # Format: provider_name:IP_prefix
    if ':' not in provider_entry:
      continue
    provider_name, ip_prefix = provider_entry.split(':', 1)
    if ip.startswith(ip_prefix):
      return (True, provider_name)
  return (False, None)

def check_tls_status(record, url, response, errors, changed):
  # If we got a valid HTTP response, check certificate organization
  if response is not None and response.status_code > 100 and response.status_code < 600:
    org = get_certificate_organization(record)
    log(f"Certificate organization for {record}: {org}", "debug")
    if org and org in safeorganizations:
      log(f"Raising score for response with correct EV SSL cert and matching organization: {record} ({records[record]['Score']} -> {records[record]['Score'] + 50}))", "debug")
      adjust_score(record, 50, "Matching TLS cert with verified organization")
    elif org and org not in safeorganizations:
      log(f"Lowering score for response with foreign organization: {record} ({records[record]['Score']} -> {records[record]['Score'] - 25}))", "debug")
      adjust_score(record, -25, "Matching TLS cert but foreign organization")
    else:
      log(f"Raising score for response with correct SSL cert: {record} ({records[record]['Score']} -> {records[record]['Score'] + 25}))", "debug")
      adjust_score(record, 25, "Matching TLS cert")

  if response is None:
    if('Hostname mismatch' in str(errors) or 'SSLError' in str(errors)):
      # Check to see what SANs the cert has. Maybe one of them is a clue.
      sans = get_tls_names(record)
      log(f"SANS for {record}", "debug")
      found = False
      for san in sans:
        if san in safedomains:
          found = True
          log(f"Raising score for {record} found TLS SAN {san} in safedomains ({records[record]['Score']} -> {records[record]['Score'] + 50})", "debug")
          adjust_score(record, 50, "Safedomain found in TLS SAN")
      if not found:
        log(f"Lowering score for response with wrong SSL cert: {record} ({records[record]['Score']} -> {records[record]['Score'] - 50}))", "debug")
        adjust_score(record, -50, "Non-matching TLS cert")
      response = None
    elif(
      'HANDSHAKE_FAILURE' in str(errors)
      or 'SSLEOFError' in str(errors)
      or 'Timeout' in str(errors)
    ):
      # Listening on 443 but failing to present a certificate, or not listening. Try again on http.
      url = url.replace('s', '', 1)
      response, errors = getHttp(url)
  return response, errors, changed

def handle_ns_record(record):
  # Check NS records for dangling potential by verifying if the NS nameserver is valid
  if('ResourceRecords' in records[record] and len(records[record]['ResourceRecords']) > 0):
    # First, validate the NS records against authoritative sources
    ns_list = [ns['Value'] for ns in records[record]['ResourceRecords']]
    has_mismatch, stale_ns, authoritative_ns = validate_ns_records(record, ns_list)

    if has_mismatch:
      if stale_ns:
        log(f"NS record validation for {record} found stale entries: {stale_ns}", "info")
        # Penalize for each stale nameserver
        for stale_server in stale_ns:
          adjust_score(record, -50, f"Stale NS record: {stale_server} (not authoritative)")
      log(f"Authoritative NS records for {record}: {authoritative_ns}", "debug")

    for ns_record in records[record]['ResourceRecords']:
      # Check score threshold to end early if already conclusive
      if records[record]['Score'] > 99 or records[record]['Score'] < -99:
        log(f"NS record score for {record} is already conclusive ({records[record]['Score']}), stopping early", "debug")
        return 0

      # Strip off trailing dot from nameserver
      ns_value = ns_record['Value']
      if ns_value.endswith('.'):
        ns_value = ns_value[:-1]
      log(f"Checking NS record for {record} pointing to nameserver {ns_value}", "debug")

      # Three ways NS records can be dangling:
      # 1. They point to a record that points to an IP address that can be taken over
      #   - How can we test this? If it times out then it might be unowned?
      # 2. They point to a nameserver that can be taken over (for instance at AWS if no matching hosted zone exists)
      #.  - At AWS, if we query the nameserver for the domain and it responds FORBIDDEN or similar, it is vulnerable.
      # 3. They point to domain that can be taken over (for instance a domain that isn't registered)
      #   - If the top level of the target domain is not registered, it's vulnerable, although exploiting it requires spending money
      #
      # Try to resolve the nameserver
      # The regular get_ipv4_by_hostname() makes assumptions that don't work well here.
      # NS records point at other records, like a CNAME, but don't directly resolve if you ask a resolver for them.
      # We're not expecting IP addresses back when we ask for the NS records.
      # Each record needs to have its own score and resolved IPs.
      # The targets of the NS records do resolve to an IP, but they aren't "ours".
      # There's also no sense in treating them like HTTP servers.
      # If any of them fail to resolve they that record is dangling.
      # If all NS records get good scores, adjust the score for the parent record.
      stats['dns_lookups'] += 1
      ips = []
      try:
        for i in socket.getaddrinfo(ns_value, 0):
          if( i[0] is socket.AddressFamily.AF_INET and (i[1] is socket.SocketKind.SOCK_STREAM) or i[1] is socket.SocketKind.SOCK_DGRAM):
            if(i[4][0] not in ips):
              ips.append(i[4][0])
            if ns_value not in records[record]:
              records[record][ns_value] = {}
            records[record][ns_value]['ips'] = sorted(ips)
          else:
            # What's the situation here? What causes this branch?
            # One time it was a different kind of socket.
            log(f"Unknown situation found for {ns_value}: {i}", "debug")
            log(json.dumps(ns_record, indent=2), "debug")
      except Exception as e:
        if(e is socket.gaierror):
          log(f"DNS failed to resolve for {ns_value}.", "debug")
          records[record][i]['Score'] = sorted(ips)
        else:
          log(f"DNS failed to resolve for {ns_value} {e}.", "debug")

      # Checking case 2.
      if ips:
        # AWS Nameservers will always resolve
        # but when you query them for the domain they will respond FORBIDDEN or something if there isn't a matching hosted zone
        # We also need to check that we own the hosted zone, because resolving IPs is what a malicious attacker does when they have captured a dangling NS record
        # We can query for SOA or NS records for the domain, or maybe an A record for the apex.
        # If the SOA or NS records resolve the zone exists so it's either not dangling or compromised.
        # If the apex resolves and is a safeip, it could still be compromised, but they're pointing at our safeips so... shrug?
        log(f"NS record {record} points to valid nameserver {ns_value} {ips}", "debug")
        adjust_ns_score(record, ns_value, 50, "NS points to valid nameserver")
        try:
          query_ns(ips[0], record, 'SOA')
        except Exception as e:
          adjust_ns_score(record, ns_value, -100, "Nameserver does not resolve SOA record for domain")
          log(f"Failed to query NS {ips[0]} for {record} SOA record: {e}", "debug")
      else:
        # If the NS records don't resolve, it's dangling
        log(f"NS record {record} points to unresolvable nameserver {ns_value}", "debug")
        adjust_ns_score(record, ns_value, -100, "NS points to unresolvable nameserver")

      log(f"Finished checking NS record: {record} -> {ns_value}", "debug")
    # After checking all NS records, pick the lowest score for the record
    lowest_ns_score = 0
    for ns_record in records[record]['ResourceRecords']:
      # Strip off trailing dot from nameserver
      ns_value = ns_record['Value']
      if ns_value.endswith('.'):
        ns_value = ns_value[:-1]
      lowest_ns_score += records[record][ns_value]['Score']
      log(f"Change overall NS record score for {record} by {lowest_ns_score}", "debug")
      adjust_score(record, lowest_ns_score, "Aggregated NS record scores")
  return 0

def handle_a_cname_record(record):
  log(f"Handling A or CNAME record: {record}", "debug")
  ips = get_ipv4_by_hostname(record)
  changed = 0

  if(not ips):
    log(f"DNS Lookup failure: {record} {ips}", "debug")
    adjust_score(record, -100, "DNS lookup failure")
    return 1

  if('ResourceRecords' not in records[record] or len(records[record]['ResourceRecords']) == 0):
    log(f"No ResourceRecords found: {record}", "debug")
    adjust_score(record, 100, f"No ResourceRecords found for {record}")
    return 1

  if(records[record]["Type"] == "A" and len(ips) > 0):
    # Check if the IP belongs to a known hosting provider
    # Being on a known hosting provider is a weak signal, but being on an unknown one is a strong negative signal.
    matched, provider = check_ip_hosting_provider(ips[0])
    if matched:
      log(f"IP {ips[0]} belongs to known hosting provider {provider} for {record} ({records[record]['Score']} -> {records[record]['Score'] + 5})", "debug")
      adjust_score(record, 5, f"IP on known hosting provider: {provider}")
      changed += 1
    else:
      log(f"IP {ips[0]} does not belong to known hosting provider for {record}", "debug")
      adjust_score(record, -25, "IP not on known hosting provider")
      changed += 1

  if(records[record]["Type"] == "A" and 'ResourceRecords' in records[record]
    and ( records[record]['ResourceRecords'][0]['Value'][:3] == '10.' or records[record]['ResourceRecords'][0]['Value'][:8] == '192.168.')):
    # On second thoughts, this isn't safe. Imagine internet cafe scenario.
    # Someone in the cafe sets their IP to the private IP returned by this record.
    # Then tricks another user in the cafe to visit the domain. They then effectively have a subdomain takeover for that one user.
    log(f"Private range safe: ({record} -> {records[record]['ResourceRecords'][0]['Value']}) ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "Private range")
    return 1

  elif(records[record]["Type"] == "CNAME"
    and records[record]['ResourceRecords'][0]['Value'] in safedomains):
    log(f"Raising score for CNAME pointing to {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "CNAME points to safedomain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and records[record]['AliasTarget']['DNSName'] in safedomains):
    log(f"Raising score for Alias pointing to {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "Alias points to safedomain")
    return 1

  elif(records[record]["Type"] == "CNAME"
    and re.findall('.*[0-9]*.eu-west-1.elb.amazonaws.com', records[record]['ResourceRecords'][0]['Value']) ):
    log(f"Raising score for CNAME pointing to high entropy ELB domain {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "CNAME points to high entropy ELB domain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and re.findall('.*[0-9]*.eu-west-1.elb.amazonaws.com', records[record]['AliasTarget']['DNSName']) ):
    log(f"Raising score for Alias pointing to high entropy domain {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "Alias points to high entropy domain")
    if(records[record]['AliasTarget']['DNSName'][:-1] not in safedomains):
        safedomains.append(records[record]['AliasTarget']['DNSName'][:-1])
    return 1

  elif(records[record]["Type"] == "CNAME"
    and re.findall(r'.*\.s3-website-eu-west-1.amazonaws.com', records[record]['ResourceRecords'][0]['Value']) ):
    log(f"Raising score for CNAME pointing to high entropy domain {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "debug")
    adjust_score(record, 100, "CNAME points to high entropy S3 domain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and re.findall('s3-website-eu-west-1.amazonaws.com', records[record]['AliasTarget']['DNSName']) ):
    log(f"Lowering score for Alias pointing to generic S3 endpoint {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] - 25})", "debug")
    adjust_score(record, -25, "Alias points to S3 endpoint")
    return changed + 1

  elif(record in timeoutDomains):
    log(f"Domain is known to time out, not requesting again: {record}", "debug")
    return changed

  elif(len(ips) > 0 and ips[0] in timeoutIPs):
    log(f"IP is known to time out, not requesting again: {record} {get_ipv4_by_hostname(record)[0]}", "debug")
    return changed

  else:
    return analyse_http(record) + changed


def adjust_score(record, score_change, reason = "Unknown"):
  records[record]['Score'] += score_change
  if 'causes' in records[record]:
    records[record]['causes'].append(reason)
  else:
    records[record]['causes'] = [reason]
  # If this score change pushes the record over a threshold (+100 or -100) then cascade changes to related domains and IPs
  if(records[record]['Score'] > 99):
    log(f"Score change for {record} means it is now safe: {records[record]['Score']}. {reason}", "debug")
    # Add domain and CNAME or Alias target to safedomains
    if(record not in safedomains):
      safedomains.append(record)
    elif(records[record]["Type"] == "CNAME"
      and records[record]['ResourceRecords'][0]['Value'] not in safedomains):
      log(f"Score change for {record} means CNAME target {records[record]['ResourceRecords'][0]['Value']} is now safe", "debug")
      safedomains.append(records[record]['ResourceRecords'][0]['Value'])
    elif(records[record]["Type"] == "A"
      and 'AliasTarget' in records[record]
      and records[record]['AliasTarget']['DNSName'] not in safedomains):
      log(f"Score change for {record} means Alias target {records[record]['AliasTarget']['DNSName']} is now safe", "debug")
      safedomains.append(records[record]['AliasTarget']['DNSName'])
  elif(records[record]['Score'] < -99):
    log(f"Score change for {record} means it is now unsafe: {records[record]['Score']}. {reason}", "debug")
  else:
    log(f"Score change for {record} leaves it still in the middle: {records[record]['Score']}", "debug")

def adjust_ns_score(record, nameserver, score_change, reason = "Unknown"):
  if nameserver not in records[record]:
    records[record][nameserver] = {}
  if 'Score' not in records[record][nameserver]:
    records[record][nameserver]['Score'] = 0
  records[record][nameserver]['Score'] += score_change
  if 'causes' in records[record]:
    records[record][nameserver]['causes'].append(reason)
  else:
    records[record][nameserver]['causes'] = [reason]

  # Check all nameservers in this record to see if they are safe or unsafe

def process_record(record):
  if(records[record]['Score'] > 99 and record in safedomains):
    log(f"Already safe: {records[record]['Score']} ({record})", "debug")
    return 0

  if(records[record]['Score'] < -99 and records[record]['Score'] > -199 ):
    log(f"Already unsafe: {records[record]['Score']} ({record})", "debug")
    return 0

  if(records[record]['Score'] > 99 and not record in safedomains):
    log(f"Already safe: {records[record]['Score']} ({record})", "debug")
    safedomains.append(record)
    return 1

  if('_' in record):
    adjust_score(record, 100, "Record with underscore")
    log(f"Ignoring records with underscores ({record})", "debug")
    return 0

  if('Type' not in records[record]):
    log(f"No Type found for record ({record})", "debug")
    return 0

  if(records[record]['Type'] == 'SOA'
    or records[record]['Type'] == 'TXT'
    or records[record]['Type'] == 'MX'
    or records[record]['Type'] == 'PTR'):
      log(f"Ignoring {records[record]['Type']} records ({records[record]['Name']})", "debug")
      return 0

  elif(records[record]['Type'] == 'A' or records[record]['Type'] == 'CNAME'):
    return handle_a_cname_record(record)

  elif(records[record]['Type'] == 'NS'):
    return handle_ns_record(record)

  elif(records[record]['Type'] not in ['A', 'CNAME', 'NS']):
    log(f"Not handled record type: {records[record]['Type']} {record}", "debug")
    return 0

def check_csp_header(record, response):
  """Check if Content-Security-Policy header contains any safedomains."""
  if response is None or 'content-security-policy' not in response.headers:
    return 0

  csp_header = response.headers.get('content-security-policy', '')
  log(f"CSP header for {record}: {csp_header}", "debug")

  changed = 0
  for safedomain in safedomains:
    if safedomain in csp_header:
      log(f"Found safedomain {safedomain} in CSP header for {record} ({records[record]['Score']} -> {records[record]['Score'] + 50})", "debug")
      adjust_score(record, 50, f"Safedomain {safedomain} found in CSP header")
      changed += 1

  return changed

def analyse_http(record):
    if record in seedurls:
        url = seedurls[record]
    else:
        url = f"https://{record}/"
    response, errors = getHttp(url)
    changed = 0

    # Handle SSL-related errors and scoring
    response, errors, changed = check_tls_status(record, url, response, errors, changed)

    if(response is None):
        if('Timeout' in str(errors)):
            log(f"Lowering score for no http(s) response: {record} ({records[record]['Score']} -> {records[record]['Score'] - 50}))", "debug")
            adjust_score(record, -50, "No http(s) response")
            changed += 1
        else:
            log(f"Other http error {str(errors)}", "debug")
    elif(response.status_code > 100 and response.status_code < 600):
        # Check CSP header for safedomains
        changed += check_csp_header(record, response)

        for safestring in safestrings:
            log(f"Looking for {safestring} in https://{record}", "debug")
            if(safestring.encode('utf-8') in response.content):
                log(f"Increasing score for safestring: {record} ({safestring}) ({records[record]['Score']} -> {records[record]['Score'] + 50})", "debug")
                adjust_score(record, 50, "Safestring found")
                changed += 1
        changed += follow_redirects(record, response, url)
    else:
        log(f"Unknown http response situation {response.headers['location']}: {record} is now {records[record]['Score']}", "debug")
    return changed

############################## Main ########################

parseOptions()
loadSafeDomains()
loadSafeIPs()
loadSafeStrings()
loadSafeOrganizations()
loadSafeHostingProviders()
loadSeedURLs()

# Load DNS records - will exit with error message if AWS credentials are invalid
if not loadDNSRecords():
    log(f"ERROR: Failed to load DNS records. Exiting.", "error")
    sys.exit(1)

if len(records) == 0:
    log(f"ERROR: No DNS records loaded. Please check your input file or AWS credentials.", "error")
    sys.exit(1)

# Main loop
# filter out everything we can without network requests
# Some of these can be taken over if they are dangling but we don't support them yet
# MX records are theoretically possible

changed = 1
while changed > 0:
    changed = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_record, record): record for record in records}
        for future in as_completed(futures):
            result = future.result()
            if result:
              changed += result
    log(f"Changed {changed} scores during this loop.", "debug")
    log(f"safedomains now contains {len(safedomains)} domains.", "debug")

# End main loop, report results and finish up

# Save records with scores to file
now = datetime.now() # current date and time
date = now.strftime("%Y-%m-%d")
filename = f"records_{date}.json"
with open(filename, 'w') as f:
  json.dump(records, f, indent=2)

summary = {'safe': 0, 'unsafe': 0, 'unknown': 0}
# Calculate results
for record in records:
  if(records[record]['Score'] <= 10):
    summary['unsafe'] = summary['unsafe'] + 1
    log(f"{record}: {records[record]['Score']}", "info")
  elif(records[record]['Score'] <= args.score):
    summary['unknown'] = summary['unknown'] + 1
    log(f"{record}: {records[record]['Score']}", "info")
  else:
    summary['safe'] = summary['safe'] + 1
    #log(f"{record}: {records[record]['Score']}", "info")

# Output results
print(json.dumps(summary, indent=2))

# If compare-to option is set, load previous records and compare (after summary/stats output)
if hasattr(args, 'compare_to') and args.compare_to:
    compare_file = args.compare_to

    # Handle special 'previous' value - find the most recent records file
    if compare_file.lower() == 'previous':
      compare_file = find_most_recent_records_file()
      if not compare_file:
        log("Cannot compare: no previous records file found", "error")
        compare_file = None

    if compare_file:
      try:
        with open(compare_file, 'r') as f:
          previous_records = json.load(f)
        compare_records(records, previous_records)
      except Exception as e:
        print(f"Error comparing to previous records: {e}")

stats['finish_time'] = time.time()
stats['total_time'] = stats['finish_time'] - stats['start_time']
stats['total_requests'] = stats['http_requests'] + stats['https_requests']
print(json.dumps(stats, indent=2))
