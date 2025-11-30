# Ownership Verification Signals

## Proposed Signals to Verify Domain Ownership

### 1. HTTP Response Headers
Check for company-specific headers that indicate infrastructure ownership:
- `Server` header (nginx vs specific infrastructure patterns)
- `X-Powered-By` headers
- `Via` headers from known CDNs
- Custom headers that match company infrastructure patterns

### 2. Response Content Analysis
Examine the actual response body for ownership indicators:
- Company branding/logo in HTML
- Company-specific meta tags or comments
- Internal tool signatures or frameworks
- Presence of known company identifiers

### 3. Certificate Details Beyond Matching
Go deeper into certificate analysis:
- Certificate issuer (internal CA vs public CAs like Let's Encrypt)
- Certificate organization field (should match company name)
- Certificate validity period patterns
- Private key control indicators

### 4. Response Body Size/Patterns
Detect placeholder or default responses:
- Empty or minimal responses (attacker placeholder)
- Default error pages vs real application content
- Specific content-length patterns that match known applications

### 5. DNS Metadata Corroboration
Cross-validate with DNS infrastructure:
- Reverse DNS matching infrastructure expectations
- IP address belonging to known hosting providers (AWS, Azure, etc.)
- IP reputation and historical data

### 6. TLS Certificate Transparency (CT) Log Analysis
Verify certificate issuance history:
- Cross-reference against known certificate registrations
- Check who requested the certificate
- Identify suspicious certificate patterns

Known registrars - Useful for domains that have expired and we no longer own. No help on subdomains. Anything else?
Known hosting providers. Good for detecting when we have changed hosting providers and left DNS records pointing at the old one.
Known technologies such as Apache or nginx. Potentially useful, but a fairly weak signal, especially if we use several.
Run any found domains (in HTML or headers) through reputation service. Subdomains that have been taken over may have malicious code using known malicious domains.
Convert various .txt files to a single config file with sections.


## Priority Implementation
Start with these most practical signals:
1. **Certificate organization field verification** - Compare against company info or add as validation
2. **Response body analysis** - Detect placeholder pages and company signatures
3. **HTTP header inspection** - Look for infrastructure-specific headers


