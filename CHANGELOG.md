# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added certificate organization field verification. When an HTTPS response is received, the code now extracts the Organization field from the SSL certificate and checks it against a list of safe organizations in `safeorganizations.txt`. This prevents dangling domains with attacker-controlled certificates from getting false positive scores (+50 for verified org, -25 for foreign org).
- Added Content-Security-Policy (CSP) header inspection. When an HTTP response is received, the code now checks if the CSP header contains any of your `safedomains`. Finding a safedomain in CSP is a strong indicator of legitimate infrastructure (+50 points per domain found).
- Added threading to evaluate each record in parallel. Cuts run time by around 90%.
- Added `--compare-to` option to compare current records to a previous set, highlighting risky differences (records that became unsafe or dropped to risky scores).
- Added support for NS records. Two checks implemented:
  - If we get no response the IP may be up for grabs.
  - If it is an AWS nameserver and we get a REFUSED response, the zone file is up for grabs.
  - The third check (not implemented) is for domains that are not registered. This seems like a pretty unlikely way to get compromised.
- Added AWS Route53 integration: use `--aws-route53` to fetch DNS records directly from your AWS account instead of a local file. Supports `--aws-profile` and `--aws-region` options. Will also pick up credentials in all the usual boto3 ways, such as the AWS_PROFILE environment variable.

## [Earlier]
- TLS cert comparison.
- Initial implementation.
