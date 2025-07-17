# 📁🔓 Path Traversal Attack (Directory Traversal)

> **OWASP Category:** A01:2021 – Broken Access Control  
> **Severity:** 🔴 High  
> **Difficulty:** 🟢 Easy

The website uses a `page` parameter to include files dynamically (e.g., `index.php?page=somepage`). The application doesn't properly validate or sanitize the input, allowing attackers to navigate outside the intended directory structure using "../" sequences to access sensitive system files.

🎯 **Classic Attack:** This is one of the oldest and most fundamental web vulnerabilities - essentially "breaking out" of the web directory jail!

---

## 🎯 Exploit Technique

### 🔧 Attack Progression
```url
# Initial attempt
https://192.168.64.2/index.php?page=../etc/passwd

# Escalating the path traversal
https://192.168.64.2/index.php?page=../../../../../../../etc/passwd
```

**Exploitation process:**
1. 🔍 Identify the vulnerable parameter (`page`)
2. 🧪 Test basic traversal: `../etc/passwd`
3. 📈 Escalate with more "../" sequences
4. 🎯 Navigate to sensitive files like `/etc/passwd`
5. 🏆 Success when reaching: `../../../../../../../etc/passwd`

### 🌍 Common Target Files

| Operating System | Target File | Purpose |
|-----------------|-------------|---------|
| 🐧 **Linux/Unix** | `/etc/passwd` | User account information |
| 🐧 **Linux/Unix** | `/etc/shadow` | Password hashes (if accessible) |
| 🪟 **Windows** | `C:\Windows\System32\drivers\etc\hosts` | Network configuration |
| 🪟 **Windows** | `C:\boot.ini` | Boot configuration |
| 🌐 **Web Apps** | `../config/database.php` | Database credentials |

---

## 🛠️ Security Implementation

### ❌ vs ✅ Comparison

| 🚫 **Vulnerable Code** | ✅ **Secure Code** |
|----------------------|------------------|
| `include($_GET['page'])` | `include(validate_page($_GET['page']))` |
| No input validation | Whitelist allowed pages |
| Direct file inclusion | Sanitize "../" sequences |

### 🔒 Defense Strategies

**Input Validation (Critical):**
- [ ] **📋 Whitelist Validation** - Only allow predefined page names
- [ ] **🧹 Path Sanitization** - Remove "../" and "./" sequences
- [ ] **📍 Absolute Paths** - Use full paths instead of relative ones
- [ ] **🔐 Access Controls** - Implement proper file permissions

**Advanced Protection:**
- [ ] **🔒 Chroot Jails** - Isolate web application directory
- [ ] **🛡️ Web Application Firewall** - Filter malicious requests
- [ ] **📊 Logging & Monitoring** - Track file access attempts
- [ ] **🎭 Security Headers** - Implement Content Security Policy

**Implementation Example:**
```php
// Secure implementation
function validate_page($page) {
    $allowed_pages = ['home', 'about', 'contact'];
    return in_array($page, $allowed_pages) ? $page : 'home';
}
```

---

## ⚠️ Risk Assessment & Impact

### 🎭 Attack Scenarios by Severity

| Risk Level | Attack Target | Business Impact | Example |
|------------|---------------|----------------|---------|
| 🔴 **Critical** | System configuration files | Complete system compromise | `/etc/passwd`, `/etc/shadow` |
| 🟠 **High** | Application config files | Database/API key exposure | `config.php`, `.env` files |
| 🟡 **Medium** | Source code exposure | Intellectual property theft | Application source files |
| 🟢 **Low** | Log files | Information disclosure | Access logs, error logs |

### 🌍 Real-World Attack Examples

| Industry | Attack Scenario | Impact |
|----------|----------------|--------|
| 🏦 **Financial** | Access customer data files | Data breach, regulatory fines |
| 🏥 **Healthcare** | Read patient record files | HIPAA violations, lawsuits |
| 🏢 **Enterprise** | Steal proprietary source code | Competitive disadvantage |
| 🛒 **E-commerce** | Access payment config files | Credit card data exposure |

### 📈 Famous Security Incidents

#### 🏆 Hall of Shame
- **🎮 Gaming Platform (2019)**  
  *Vulnerability:* Path traversal in file upload  
  *Impact:* 100M+ user records exposed  
  *Cost:* $50M+ in fines and remediation

- **🏢 Enterprise Software (2020)**  
  *Vulnerability:* Directory traversal in admin panel  
  *Impact:* Source code of major products leaked  
  *Lesson:* Even "admin-only" features need validation

- **☁️ Cloud Provider (2021)**  
  *Vulnerability:* Path traversal in backup system  
  *Impact:* Customer data cross-contamination  
  *Fix:* Complete architecture redesign

---

## 🧠 Security Mindset

### 💭 Key Principles

> 🔐 **Golden Rule #1:** "Never trust user input to construct file paths"

> 🕵️ **Golden Rule #2:** "Validate, sanitize, then validate again"

> 🛡️ **Golden Rule #3:** "Principle of least privilege - limit file system access"

### 🎯 Developer Defense Tactics

| Principle | Implementation | Example |
|-----------|----------------|---------|
| **📋 Whitelist Approach** | Only allow known-good values | `['home', 'about', 'contact']` |
| **🧹 Input Sanitization** | Remove dangerous characters | Strip "../" sequences |
| **📍 Absolute Paths** | Use full filesystem paths | `/var/www/pages/home.php` |
| **🔒 Sandboxing** | Restrict file access scope | Chroot to web directory |

---

## 🚨 Detection & Monitoring

### 🔍 Warning Signs
- Multiple "../" sequences in URL parameters
- Requests for system files (`/etc/passwd`, `/boot.ini`)
- Unusual file access patterns in logs
- 404 errors for system directories

### 📊 Monitoring Implementation
```bash
# Log analysis for path traversal attempts
grep -E "\.\./|\.\.\\|etc/passwd|boot\.ini" /var/log/apache2/access.log
```

---

## 🔗 Learning Resources

### 📚 Educational Materials
- [OWASP Path Traversal Guide](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [SANS Secure Coding: File System Access](https://www.sans.org/white-papers/2172/)

### 🛠️ Testing Tools
- **Burp Suite** - Automated path traversal detection
- **OWASP ZAP** - Directory traversal scanner
- **DirBuster** - Directory and file enumeration
- **Nikto** - Web server vulnerability scanner

### 🎯 Practice Platforms
- **DVWA** - Damn Vulnerable Web Application
- **WebGoat** - OWASP learning platform
- **Metasploitable** - Intentionally vulnerable Linux

---

*Remember: The file system is not your friend when it comes to user input - always assume malicious intent! 📁🔐* 