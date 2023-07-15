# DanglingDNS
DanglingDNS is a tool for examining your DNS records to detect whether any of them is at risk of being taken over.

# What is a "Dangling DNS" record and what risk do they pose?
A Dangling DNS record is a record that points to an IP address that you don't control. These can come about when you change website hosting provider or decommission an old product or when a third-party service you use goes bankrupt. The vulnerability is also known as a "subdomain takeover".

The risk they pose is that someone else will one day gain control of that IP address and will then be able to host a website on a subdomain of your main domain. This may allow them to receive cookies from the visitors to your website that your main website set or set cookies that will be sent to your main website. They will also be able to get an SSL certificate for the domain that points to their IP address.

A dangling MX record will mean that any email sent to that domain will be received by whoever now controls the IP address

# How does it work?
DanglingDNS works by making HTTP requests to your DNS records and looking for clues in the responses (or lack of response) that the IP address it points to is controlled by you. Clues can be either positive (more likely that you control the IP) or negative (less likely that you own the IP). The positive clues are based on information that you put into the "safe" configuration files. For instance, if you use Google Analytics on your sites then the HTTP responses will contain your Google Analytics ID. The same works for your Facebook and Twitter IDs if you have social media buttons on your website.
If you own a range of IP addresses you can put those into the safeips file.

These HTTP requests can take a long time to complete, especially for domains that point to an IP address without any website running on it currently. To speed up the scan, we keep track of all the IPs and domains we have determined are safe and skip making HTTP requests for any DNS record that point to something we have already determined is safe. A future improvement will be to add threading to run the requests in parallel.

Any positive signal improves the score of the DNS record and the IP(s) it points to, including a chain of CNAME records that eventually point to the IP(s). When the score is high enough, all the records and IPs are considered "safe".

Positive signals:
-  The record points to another record that we own. (Determining safety is delegated to the target.)
-  The record is a CNAME and points to something with high entropy.
-    This is something like a Beanstalk, Heroku or Sendgrid domain.
    The domain that you point your DNS record to is auto-generated and is unique to you and cannot be used if you lose it.
    We could maybe just hard-code that `*.elasticbeanstalk.com` and `*.herokudns.com` as a target are safe.
-  A record that points to an S3 bucket is safe if we can also verify that we own the bucket.
-  The record responds to an HTTP request and the content contains one of our GA IDs.
-  The record responds to an HTTP request and the content contains our static assets domains.
-  The record responds to an HTTP request with a redirect to domain we own
-  The record responds to an HTTPs request with a valid certificate (as long as the CA is not LetsEncrypt)
-    LetsEncrypt will issue a certificate based on being able to serve a specific HTML file on the domain.
-  The record points to an IP address we own.
-  Private range IP addresses. The usual risks of dangling DNS don't apply to private ranges.
-    There might be other reasons don't want these in public DNS.

Signals that seem good at first but turn out to be bad
-  The record points to a known partner (domain or IP address we don't own)
-    This just amounts to having a second copy of the DNS record, which goes out of date at the same time as the DNS record.

Negative signals:
-  The record responds to an HTTP request and the content contains a GA ID that we do not own.
-  The record responds to an HTTP request with a redirect to domain we do not own such as www.google.com
-  The record points to an S3 bucket and responds with a "bucket does not exist" response.

Suspicious signals
-  The record points to an S3 bucket but we can't verify that we own the bucket.
-  The record points to an unknown domain
-    This is really just the "known domain" pattern which I already think isn't a good idea.
