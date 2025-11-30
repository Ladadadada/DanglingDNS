# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- Added `--dns-servers` option to specify custom DNS servers for resolution. Pass a comma-separated list of IP addresses (e.g., `--dns-servers 8.8.8.8,1.1.1.1`) to override system default resolvers. Useful for testing with specific DNS configurations, private DNS services, or when running in restricted network environments. System defaults are used if this option is not provided.
- Added NS record validation against authoritative nameservers. When processing NS records, the code now queries the authoritative nameservers and compares them against what's stored in Route53. This detects stale or misconfigured NS records that may indicate DNS configuration errors. Each stale nameserver found results in -50 points. This helps identify outdated DNS records that could represent security risks if not resolved.
- Added known hosting provider IP detection. When an A record resolves, the code checks if the IP belongs to a known hosting provider (AWS, Azure, GCP, etc.) configured in `safehostingproviders.txt`. IPs matching known providers are awarded +5 points, as this is a weak signal.
Not being on a known hosting provider is a fairly strong negative signal.
Pre-populated example file includes common providers.
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
