# DanglingDNS
DanglingDNS is a tool for examining your DNS records to detect whether any of them is at risk of being taken over.

# What is a "Dangling DNS" record and what risk do they pose?
A Dangling DNS record is a record that points to an IP address that you don't control. These can come about when you change website hosting provider or decommission an old product or when a third-party service you use goes out of business. The vulnerability may also be known as a "subdomain takeover", especially when it is exploited by a bug bounty hunter or malicious attacker.

The risk they pose is that someone else will one day gain control of that IP address and will then be able to host a website on a subdomain of your main domain. This may allow them to receive cookies from the visitors to your website that your main website set or set cookies that will be sent to your main website. They will also be able to get an SSL certificate for the domain that points to their IP address.

A dangling MX record will mean that any email sent to that domain will be received by whoever now controls the IP address.

Dangling NS records can also be taken over. When this happens the attacker gains control over all the DNS records for the subdomain and everything under it.

# Who is this tool for?
It could potentially be used by anyone who owns or controls a domain and would provide different benefits in different ways to businesses of different sizes.

At a startup you often only have one domain with a handful of subdomains. It's only a few minutes work to look through them manually and verify that they are all pointing at an IP address you control. But you probably only do this monthly at best and more likely yearly when your security audit comes around. DanglingDNS can be configured to run daily and alert you to any dangling DNS records as soon as they happen.

At a medium sized business the DNS landscape can be more complicated. You may have many domains and hundreds of DNS records built up over decades, managed by different areas of the business that all operate on their own schedule. Manually running through all your records centrally becomes a daunting task even on a yearly basis and the various teams don't necessarily have the security training, understanding or incentive to do the job themselves.

At a large business where the number of DNS records is in the tens or hundreds of thousands nearly all of these will be created automatically by scripts or infrastructure as code and will be created and destroyed along with the resources they point to. You may also own your own IP address ranges and even data centres. Dangling DNS records will be an almost non-existant problem, however the stakes are much higher at this scale and if even a single record is taken over the number of users compromised could be in the millions. The more quickly you can detect and remove at-risk records the better. A daily scan of the entire estate or subsets of records is one way to reduce that risk.

Security researchers, bug bounty hunters, red teams and penetration testers already have tools to guess what subdomains exist for a given domain but still face the same problem when trying to categorise them. DanglingDNS can help you rule out the records that are safe and concentrate on investigating the risky ones.

# What does it do?
Given a list of domains and some hints about the sorts of things you include on your websites, DanglingDNS will try to categorise each domain as either safe or at risk. This will help you narrow down the list to look at manually and present them to you in the priority order they should be looked at.

Due to the nature of these things it is difficult for even humans to say with certainty that a record is dangling or not, and this tool is not as smart as a human. It definitely gets things wrong and you should not blindly trust the results of the tool and delete any domains it thinks are unsafe. But if you investigate the domains in the order it presents them you can maximise your impact while minimising your effort.

If you run it daily and save the output, you can compare it to the previous day's output to identify changes. This goes beyond just detecting changes in your DNS records or IP addresses but looks at the underlying web pages being returned on those domains. Assuming you have already manually verified all your domains, a change is worth investigating, especially one that moves a record from safe to unsafe.

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
-    There might be other reasons don't want private IP ranges in public DNS.

Signals that seem good at first but turn out to be bad
-  The record points to a known partner (domain or IP address we don't own)
    If you put IP addresses that you don't own in the safeips file it can lead you to a false sense of security.
    This just amounts to having a second copy of the DNS record, which goes out of date at the same time as the DNS record.

Negative signals:
-  The record responds to an HTTP request and the content contains a GA ID that we do not own.
-  The record responds to an HTTP request with a redirect to domain we do not own such as www.google.com
-  The record points to an S3 bucket and responds with a "bucket does not exist" response.
     This is a high risk situation. It is very easy for an attacker to create the bucket in an account they own and take over your subdomain.

Suspicious signals
-  The record points to an S3 bucket but we can't verify that we own the bucket.
-  The record points to an unknown domain
-    This is really just the "known domain" pattern which I already think isn't a good idea.
-  An HTTPS response includes an SSL certificate that does not contain the record or the parent domain name.
-    Except if the certificate presented is for a valid domain. Lots of parked domains only work on http.
