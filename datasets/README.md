# 📊 Dataset Features Description

This dataset contains 30 features used to detect phishing websites based on URL, domain, and webpage behavior.

## 🔹 Feature Encoding

* `1` → Legitimate
* `0` → Suspicious (only for some features)
* `-1` → Phishing

---

## 🔹 Address Bar Based Features

### 1. Having_IP_Address

This feature checks whether the URL uses an IP address instead of a domain name. Phishing sites often use IP addresses to hide their identity.

* `-1` → IP address used
  Example: `http://192.168.0.1/login`
* `1` → Domain name used
  Example: `https://google.com`

---

### 2. URL_Length

This feature checks the length of the URL. Very long URLs are often used to hide malicious content.

* `1` → Short URL
  Example: `https://google.com`
* `0` → Medium length
  Example: `https://example.com/login/account`
* `-1` → Very long URL
  Example: `https://secure-update-account-login-verification-paypal.com/...`

---

### 3. Shortining_Service

This checks if the URL is shortened using services like bit.ly, which can hide the real destination.

* `-1` → Shortened URL
  Example: `bit.ly/abc123`
* `1` → Normal URL
  Example: `https://amazon.com/product`

---

### 4. having_At_Symbol

Checks if the URL contains the “@” symbol, which can trick users by hiding the real address.

* `-1` → “@” present
  Example: `http://login@fake.com`
* `1` → Not present
  Example: `https://google.com`

---

### 5. double_slash_redirecting

Checks for extra “//” in the URL path, which may redirect users to another site.

* `-1` → Abnormal “//”
  Example: `http://site.com//phishing.com`
* `1` → Normal
  Example: `https://google.com/home`

---

### 6. Prefix_Suffix

Checks if the domain contains a hyphen (-), often used to mimic legitimate websites.

* `-1` → Hyphen present
  Example: `paypal-secure-login.com`
* `1` → No hyphen
  Example: `paypal.com`

---

### 7. having_Sub_Domain

Checks the number of subdomains. Too many subdomains can indicate phishing.

* `1` → No subdomain
  Example: `google.com`
* `0` → One subdomain
  Example: `mail.google.com`
* `-1` → Multiple subdomains
  Example: `login.secure.paypal.verify.com`

---

### 8. SSLfinal_State

Checks whether the website uses HTTPS and if the certificate is trustworthy.

* `1` → Valid HTTPS
  Example: `https://google.com`
* `0` → Suspicious HTTPS
  Example: self-signed certificate
* `-1` → No HTTPS
  Example: `http://fake-site.com`

---

### 9. Domain_registeration_length

Checks how long the domain is registered for. Phishing domains are usually short-lived.

* `1` → Long registration
  Example: domain registered for 5 years
* `-1` → Short registration
  Example: domain registered for a few months

---

### 10. Favicon

Checks if the website’s icon (favicon) is loaded from the same domain.

* `1` → Same domain
  Example: favicon from `google.com`
* `-1` → External domain
  Example: favicon from another site

---

### 11. port

Checks if the website uses standard ports. Non-standard ports can indicate suspicious activity.

* `1` → Standard ports (80, 443)
* `-1` → Non-standard ports
  Example: port 8080

---

### 12. HTTPS_token

Checks if the word “https” is misleadingly used inside the domain name.

* `-1` → Misleading token present
  Example: `https-login-paypal.com`
* `1` → Not present
  Example: `paypal.com`

---

## 🔹 Abnormal Based Features

### 13. Request_URL

Checks whether webpage resources (images, videos) are loaded from the same domain.

* `1` → Same domain
* `-1` → External domains

---

### 14. URL_of_Anchor

Checks whether anchor links point to valid or suspicious destinations.

* `1` → Safe links
* `0` → Suspicious (empty links like `#`)
* `-1` → Unsafe links (external domains)

---

### 15. Links_in_tags

Checks links inside meta, script, and link tags.

* `1` → Same domain
* `0` → Mixed
* `-1` → External domains

---

### 16. SFH (Server Form Handler)

Checks where form data is submitted.

* `1` → Same domain
* `0` → Blank or unclear
* `-1` → Different domain

---

### 17. Submitting_to_email

Checks if user data is sent directly via email.

* `-1` → Uses email
  Example: `mailto:attacker@gmail.com`
* `1` → Does not

---

### 18. Abnormal_URL

Checks if the domain identity matches WHOIS information.

* `-1` → Mismatch
* `1` → Match

---

## 🔹 HTML & JavaScript Based Features

### 19. Redirect

Checks how many times the page redirects.

* `0` → Few redirects
* `1` → Many redirects

---

### 20. on_mouseover

Checks if JavaScript changes the link when hovering.

* `-1` → Suspicious behavior
* `1` → Normal

---

### 21. RightClick

Checks if right-click is disabled.

* `-1` → Disabled
* `1` → Enabled

---

### 22. popUpWidnow

Checks if popups request user data.

* `-1` → Popups used
* `1` → No popups

---

### 23. Iframe

Checks for hidden iframe usage.

* `-1` → Present
* `1` → Not present

---

## 🔹 Domain Based Features

### 24. age_of_domain

Checks how old the domain is.

* `1` → Old domain
* `-1` → New domain

---

### 25. DNSRecord

Checks if the domain exists in DNS records.

* `1` → Exists
* `-1` → Not found

---

### 26. web_traffic

Checks how popular the website is.

* `1` → High traffic
* `0` → Medium
* `-1` → Low or unknown

---

### 27. Page_Rank

Checks importance of the website.

* `1` → High rank
* `-1` → Low rank

---

### 28. Google_Index

Checks if the website appears in Google search results.

* `1` → Indexed
* `-1` → Not indexed

---

### 29. Links_pointing_to_page

Checks how many other websites link to this page.

* `1` → Many backlinks
  Example: `wikipedia.org`
* `0` → Few backlinks
* `-1` → No backlinks
  Example: phishing page

---

### 30. Statistical_report

Checks whether the website’s domain or IP is listed in known phishing databases (like PhishTank).

* `-1` → Listed in phishing reports
  Example: `fake-paypal-login.com`
* `1` → Not listed
  Example: `google.com`

---

## 🔹 Final Target 

* `1` → Legitimate Website
* `-1` → Phishing Website

👉 This is a binary classification problem.
