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


import json
from pprint import pprint
import os
import time
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
  'start_time': time.time()
}

# Progress meter. Count the number of records during loading. Show percentage that are certain.

args = None

safedomains = []
safeips = []
safestrings = []
safeorganizations = []
seedurls = {}

records={}

timeoutIPs = []
timeoutDomains = []

def parseOptions():
  # Potential options:
  # -d --debug debug mode
  # -s --score <number> The maximum score to include in the output. Anything higher than this will not be printed.

  # -i input domains file

  parser = argparse.ArgumentParser(description='Dangling DNS evaluator.')

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

  global args
  args = parser.parse_args()

  print("Parsed args:")
  print(f"Debug: {args.debug}")
  print(f"Score: {args.score}")
  if args.aws_route53:
    print(f"AWS Route53 mode enabled")
    print(f"AWS Profile: {args.aws_profile if args.aws_profile else 'default'}")
  else:
    print(f"Input file: {args.input}")

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
      print(f"Adding \"{line}\" to safedomains")
      safedomains.append(line)
  #  else:
  #    print(f"Not adding \"{line}\" to safedomains")
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
      print(f"Adding \"{line}\" to safeips")
      safeips.append(line)
  #  else:
  #    print(f"Not adding \"{line}\" to safeips")
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
      print(f"Adding \"{line}\" to safestrings")
      safestrings.append(line)
    else:
      print(f"Not adding \"{line}\" to safestrings")
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
      print(f"Adding \"{line}\" to safeorganizations")
      safeorganizations.append(line)
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
      print(f"Adding {domain}: {line} to seedurls")
      seedurls[domain] = line
    else:
      print(f"Not adding anything from {origLine} to seedurls")

def loadDNSRecordsFromAWS():
  log(f"Loading DNS records from AWS Route53.", "debug")
  try:
    session = boto3.Session(profile_name=args.aws_profile, region_name=args.aws_region)
    route53 = session.client('route53')

    # List all hosted zones
    paginator = route53.get_paginator('list_hosted_zones')
    for page in paginator.paginate():
      for zone in page['HostedZones']:
        zone_id = zone['Id']
        zone_name = zone['Name'].rstrip('.')
        log(f"Processing hosted zone: {zone_name}", "debug")

        # List all records in this zone
        record_paginator = route53.get_paginator('list_resource_record_sets')
        for record_page in record_paginator.paginate(HostedZoneId=zone_id):
          for record_set in record_page['ResourceRecordSets']:
            if record_set['Type'] in ['A', 'CNAME', 'NS']:
              record_name = record_set['Name'].rstrip('.')
              resource_records = [{'Value': rr['Value']} for rr in record_set.get('ResourceRecords', [])]
              records[record_name] = {
                'Name': record_name,
                'Type': record_set['Type'],
                'ResourceRecords': sorted(resource_records, key=lambda d: d['Value']),
                'Score': 0
              }
    log(f"Finished loading {len(records)} records from AWS Route53.", "debug")
    return True
  except Exception as e:
    print(f"Error loading records from AWS Route53: {e}")
    return False

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
    print(f"{datetime.now()} {message}")

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
      log(f"Slow response from {url}: {time.time() - start_time}", "tmpdebug")
    return response, None
  except requests.exceptions.SSLError as e:
    log(f"SSL error: {e} caused by {url}", "tmpdebug")
    return None, e
  except Exception as e:
    stats['wait_time'] += (time.time() - start_time)
    log(f"HTTP error: {e} caused by {url}", "tmpdebug")
    if(time.time() - start_time > 3):
      domain = urlparse(url).netloc
      ips = get_ipv4_by_hostname(domain)
      for ip in ips:
        if(ip in timeoutIPs):
          log(f"IP {ip} already in timeoutIPs from {domain}.", "tmpdebug")
        else:
          log(f"Adding IP {ip} to timeoutIPs from {domain}.", "tmpdebug")
          timeoutIPs.append(ip)
      log(f"Slow response from {url}: {time.time() - start_time}. Adding {ips} to timeoutIPs", "tmpdebug")
    return None, e

def follow_redirects(record, response, url):
    changed = 0
    redirectchain = 0
    while(response is not None and 'location' in response.headers and redirectchain < 10):
        # If the redirect target is on the safe list, add 100.
        domain = urlparse(response.headers['location']).netloc
        if(domain in safedomains):
            log(f"Raising score for redirect to safedomain {response.headers['location']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
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

def check_tls_status(record, url, response, errors, changed):
  # If we got a valid HTTP response, check certificate organization
  if response is not None and response.status_code > 100 and response.status_code < 600:
    org = get_certificate_organization(record)
    log(f"Certificate organization for {record}: {org}", "debug")
    if org and org in safeorganizations:
      log(f"Raising score for response with correct EV SSL cert and matching organization: {record} ({records[record]['Score']} -> {records[record]['Score'] + 50}))", "tmpdebug")
      adjust_score(record, 50, "Matching TLS cert with verified organization")
    elif org and org not in safeorganizations:
      log(f"Lowering score for response with foreign organization: {record} ({records[record]['Score']} -> {records[record]['Score'] - 25}))", "tmpdebug")
      adjust_score(record, -25, "Matching TLS cert but foreign organization")
    else:
      log(f"Raising score for response with correct SSL cert: {record} ({records[record]['Score']} -> {records[record]['Score'] + 25}))", "tmpdebug")
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
        log(f"Lowering score for response with wrong SSL cert: {record} ({records[record]['Score']} -> {records[record]['Score'] - 50}))", "tmpdebug")
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

  if(records[record]['Score'] > 99 and record in safedomains):
    log(f"Already safe: {records[record]['Score']} ({record})", "debug")
    return 0

  elif(records[record]['Score'] < -99 and records[record]['Score'] > -199 ):
    log(f"Already unsafe: {records[record]['Score']} ({record})", "debug")
    return 0

  elif(records[record]['Score'] > 99 and not record in safedomains):
    log(f"Already safe: {records[record]['Score']} ({record})", "debug")
    safedomains.append(record)
    return 1

  elif(not ips):
    log(f"DNS Lookup failure: {record} {ips}", "debug")
    adjust_score(record, -100, "DNS lookup failure")
    return 0

  elif('ResourceRecords' not in records[record] or len(records[record]['ResourceRecords']) == 0):
    log(f"No ResourceRecords found: {record}", "debug")
    adjust_score(record, 100, f"No ResourceRecords found for {record}")
    return 0

  elif(records[record]["Type"] == "A" and 'ResourceRecords' in records[record]
    and ( records[record]['ResourceRecords'][0]['Value'][:3] == '10.' or records[record]['ResourceRecords'][0]['Value'][:8] == '192.168.')):
    log(f"Private range safe: ({record} -> {records[record]['ResourceRecords'][0]['Value']}) ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "Private range")
    return 1

  elif(records[record]["Type"] == "CNAME"
    and records[record]['ResourceRecords'][0]['Value'] in safedomains):
    log(f"Raising score for CNAME pointing to {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "CNAME points to safedomain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and records[record]['AliasTarget']['DNSName'] in safedomains):
    log(f"Raising score for Alias pointing to {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "Alias points to safedomain")
    return 1

  elif(records[record]["Type"] == "CNAME"
    and re.findall('.*[0-9]*.eu-west-1.elb.amazonaws.com', records[record]['ResourceRecords'][0]['Value']) ):
    log(f"Raising score for CNAME pointing to high entropy ELB domain {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "CNAME points to high entropy ELB domain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and re.findall('.*[0-9]*.eu-west-1.elb.amazonaws.com', records[record]['AliasTarget']['DNSName']) ):
    log(f"Raising score for Alias pointing to high entropy domain {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "Alias points to high entropy domain")
    if(records[record]['AliasTarget']['DNSName'][:-1] not in safedomains):
        safedomains.append(records[record]['AliasTarget']['DNSName'][:-1])
    return 1

  elif(records[record]["Type"] == "CNAME"
    and re.findall(r'.*\.s3-website-eu-west-1.amazonaws.com', records[record]['ResourceRecords'][0]['Value']) ):
    log(f"Raising score for CNAME pointing to high entropy domain {records[record]['ResourceRecords'][0]['Value']}: {record} ({records[record]['Score']} -> {records[record]['Score'] + 100})", "tmpdebug")
    adjust_score(record, 100, "CNAME points to high entropy S3 domain")
    return 1

  elif(records[record]["Type"] == "A"
    and 'AliasTarget' in records[record]
    and re.findall('s3-website-eu-west-1.amazonaws.com', records[record]['AliasTarget']['DNSName']) ):
    log(f"Lowering score for Alias pointing to generic S3 endpoint {records[record]['AliasTarget']['DNSName']}: {record} ({records[record]['Score']} -> {records[record]['Score'] - 25})", "tmpdebug")
    adjust_score(record, -25, "Alias points to S3 endpoint")
    return 1

  elif(record in timeoutDomains):
    log(f"Domain is known to time out, not requesting again: {record}", "tmpdebug")
    return 0

  elif(len(ips) > 0 and ips[0] in timeoutIPs):
      log(f"IP is known to time out, not requesting again: {record} {get_ipv4_by_hostname(record)[0]}", "tmpdebug")
      return 0

  else:
        return analyse_http(record)


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
    log(f"Score change for {record} leaves it still in the middle: {records[record]['Score']}", "info")

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
    if('_' in record):
        adjust_score(record, 100, "Record with underscore")
        log(f"Ignoring records with underscores ({record})", "debug")
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
      log(f"Found safedomain {safedomain} in CSP header for {record} ({records[record]['Score']} -> {records[record]['Score'] + 50})", "tmpdebug")
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
            log(f"Lowering score for no http(s) response: {record} ({records[record]['Score']} -> {records[record]['Score'] - 50}))", "tmpdebug")
            adjust_score(record, -50, "No http(s) response")
            changed += 1
        else:
            log(f"Other http error {str(errors)}", "tmpdebug")

    elif(response.status_code > 100 and response.status_code < 600):
        # Check CSP header for safedomains
        changed += check_csp_header(record, response)

        for safestring in safestrings:
            log(f"Looking for {safestring} in https://{record}", "debug")
            if(safestring.encode('utf-8') in response.content):
                log(f"Increasing score for safestring: {record} ({safestring}) ({records[record]['Score']} -> {records[record]['Score'] + 50})", "tmpdebug")
                adjust_score(record, 50, "Safestring found")
                changed += 1
        changed += follow_redirects(record, response, url)
    else:
        log(f"Unknown http response situation {response.headers['location']}: {record} is now {records[record]['Score']}", "tmpdebug")
    return changed

############################## Main ########################

parseOptions()
loadSafeDomains()
loadSafeIPs()
loadSafeStrings()
loadSafeOrganizations()
loadSeedURLs()
loadDNSRecords()

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
    log(f"Changed {changed} scores during this loop.", "tmpdebug")
    log(f"safedomains now contains {len(safedomains)} domains.", "tmpdebug")

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
    try:
        with open(args.compare_to, 'r') as f:
            previous_records = json.load(f)
        compare_records(records, previous_records)
    except Exception as e:
        print(f"Error comparing to previous records: {e}")

stats['finish_time'] = time.time()
stats['total_time'] = stats['finish_time'] - stats['start_time']
stats['total_requests'] = stats['http_requests'] + stats['https_requests']
print(json.dumps(stats, indent=2))
