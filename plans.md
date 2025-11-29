# Ownership Verification Signals

## Problem
The domain `which.blog` is getting a positive score because of matching SSL certificate, but this doesn't guarantee ownership - a dangling DNS record can still point to attacker infrastructure with a valid SSL cert.

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

Known registrars
Known hosting providers
Known technologies such as Apache or nginx


## Priority Implementation
Start with these most practical signals:
1. **Certificate organization field verification** - Compare against company info or add as validation
2. **Response body analysis** - Detect placeholder pages and company signatures
3. **HTTP header inspection** - Look for infrastructure-specific headers

## Implementation: Certificate Organization Field

### Configuration
Add a new config file `safeorganizations.txt` containing company names/organizations that own our certificates:
- One organization per line
- These should match the Organization (O) field in the certificate subject
- Examples: "Example Inc.", "Example Corporation", "Example Ltd"

### Code Changes Required

1. **Load safe organizations** (similar to `loadSafeDomains()`)
   - New function `loadSafeOrganizations()`
   - Parse `safeorganizations.txt`
   - Store in global `safeorganizations` list

2. **Extract certificate organization** (enhance `get_tls_names()`)
   - Already getting the certificate, add extraction of Organization field
   - Return organization name along with SANs
   - New function: `get_certificate_organization(domain)`

3. **Score adjustment in `check_tls_status()`**
   - When we get a valid response AND matching SSL cert:
     - Extract organization from certificate
     - If organization in `safeorganizations`: +50 points (ownership verified)
     - If organization NOT in `safeorganizations`: -25 points (suspicious cert)
     - If organization extraction fails: no change (neutral)

### Logic Flow
```
Valid HTTP response + matching TLS cert:
  → Extract certificate organization
    → Organization in safeorganizations? 
      → YES: +50 (ownership verified)
      → NO: -25 (foreign certificate, likely dangling)
    → No organization found?
      → Neutral (keep existing +25 from response)
```

This prevents dangling domains with attacker-controlled certificates from getting a false positive score.
