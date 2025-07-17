# 🔀 Open Redirect Attack

> **OWASP Category:** A03:2021 – Injection  
> **Severity:** 🟡 Medium  
> **Difficulty:** 🟢 Easy

The website footer contains links that redirect users to social media sites using a URL parameter (e.g., `index.php?page=redirect&site=facebook`). The value of the `site` parameter is not properly validated, allowing attackers to redirect users to arbitrary sites.

🎯 **Fun Fact:** Open redirects are often called the "gateway drug" of web vulnerabilities because they're easy to exploit but can lead to much more serious attacks!

---

## 🎯 Exploit

**Attack Vector:**
```url
Original: index.php?page=redirect&site=facebook
Malicious: index.php?page=redirect&site=evil-site.com
```

By changing the value of the `site` parameter from legitimate values ('facebook', 'twitter', 'instagram') to another value, an attacker can trigger a redirect to any site of their choice.

### 🕸️ Real-World Attack Scenario

| Step | Actor | Action |
|------|-------|--------|
| 1️⃣ | 🔴 Attacker | Creates malicious link: `legitimate-site.com/redirect?site=evil-phishing-site.com` |
| 2️⃣ | 👤 Victim | Clicks the link, trusting the legitimate domain |
| 3️⃣ | 🌐 Browser | Redirects to attacker's phishing site |
| 4️⃣ | 👤 Victim | Enters credentials, thinking they're on the legitimate site |
| 5️⃣ | 🔴 Attacker | **SUCCESS** - Steals credentials |

---

## 🛠️ How to Fix

### 🔒 Security Controls

| Control Type | Implementation | Example |
|-------------|----------------|---------|
| **🛡️ Allowlist** | Maintain server-side list of approved URLs | `['facebook.com', 'twitter.com', 'instagram.com']` |
| **🧹 Validation** | Sanitize all redirect parameters | Check against regex patterns |
| **📍 Relative Paths** | Use internal references when possible | `/social/facebook` instead of full URLs |
| **⚠️ Warning Pages** | Alert users about external redirects | Like Twitter's "You are leaving" page |

**Implementation checklist:**
- [ ] Validate and sanitize all redirect parameters
- [ ] Implement server-side allowlist for destinations
- [ ] Use relative paths for internal navigation
- [ ] Add warning pages for external redirects
- [ ] Log all redirect attempts for monitoring

---

## ⚠️ Dangers & Impact

### 🎭 Attack Types

| Attack | Risk Level | Description |
|--------|------------|-------------|
| **🎣 Phishing** | 🔴 High | Exploit user trust in legitimate domains |
| **🔑 OAuth Theft** | 🟠 Medium | Chain with OAuth flows to steal tokens |
| **🦠 Malware** | 🟠 Medium | Redirect to malware distribution sites |
| **🔍 SEO Poison** | 🟡 Low | Search engines index malicious content |

### 📅 Notable Security Incidents

#### 🏛️ Major Platform Breaches
- **🐙 GitHub (2012)**  
  *Impact:* Users redirected to credential-harvesting sites  
  *Fix:* Implemented strict URL validation

- **🔍 Google (2020)**  
  *Impact:* Multiple services affected  
  *Scale:* Millions of potential victims

- **📘 Facebook/Meta (Ongoing)**  
  *Status:* Continuous patching of redirect vulnerabilities  
  *Learning:* Even tech giants struggle with this issue

---

## 💡 Pro Security Tips

> 🛡️ **For Users:** Always check the actual destination before clicking suspicious links, even from trusted sources!

> 👨‍💻 **For Developers:** Remember - if a parameter controls navigation, it needs validation!

---

## 🔗 References & Resources
- [OWASP Open Redirect Guide](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/open-redirects) 