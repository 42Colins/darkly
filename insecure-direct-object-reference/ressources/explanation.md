# 🔓🎯 Insecure Direct Object Reference (IDOR) - Hidden Field Manipulation

> **OWASP Category:** A01:2021 – Broken Access Control  
> **Severity:** 🔴 High  
> **Difficulty:** 🟢 Easy

The 'I forgot my password' page contains a hidden email field pre-filled with `webmaster@borntosec.com`. This classic IDOR vulnerability allows users to manipulate the hidden field to change the email address and receive the password reset or flag at an arbitrary address, demonstrating how client-side data should never be trusted for access control decisions.

🎯 **IDOR Classic:** This is a textbook example of Insecure Direct Object Reference - manipulating object identifiers to access unauthorized resources!

💡 **This vulnerability is more common than you might think!** Many developers assume that hidden fields are secure because they're not visible to regular users, but they're easily discoverable through browser developer tools.

---

## 🎯 Exploit

**Step-by-step attack:**
1. Navigate to the password recovery page
2. Open browser developer tools (F12)
3. Locate the hidden `mail` input field 
4. Modify the value to an attacker-controlled email (e.g., `cprojean@student.42lyon.fr`)
5. Submit the form to receive the password reset/flag

### 🌍 Real-World Example
> In **2019**, a major e-commerce platform had a similar vulnerability where attackers could change hidden user ID fields in password reset forms, allowing them to reset passwords for arbitrary accounts.

---

## 🛠️ How to Fix

| ❌ **Bad Practice** | ✅ **Best Practice** |
|-------------------|-------------------|
| Trust client-side data | Validate all input server-side |
| Use hidden fields for sensitive data | Store sensitive data in server sessions |
| Rely on "security through obscurity" | Implement proper authentication |

**Implementation checklist:**
- [ ] **Never trust client-side input** - treat all browser data as potentially malicious
- [ ] Always verify user identity before sending password reset emails
- [ ] Use server-side sessions or tokens to determine recipients
- [ ] Implement proper authentication checks for sensitive operations

---

## ⚠️ Dangers

### 🎭 Attack Scenarios

| Threat | Impact | Example |
|--------|--------|---------|
| **Account Takeover** | 🔴 Critical | Hijack password resets for any account |
| **Data Breaches** | 🟠 High | Sensitive info sent to wrong recipients |
| **Corporate Espionage** | 🟠 High | Access to executive accounts |
| **Financial Loss** | 🟡 Medium | Compromised customer accounts |

### 📈 Historical Impact
🏢 **Major platforms affected:** Facebook, Instagram, various banking applications  
📊 **Scale:** Millions of compromised accounts across multiple incidents  
💰 **Cost:** Millions in damages and remediation efforts

---

## 🔗 References
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-472: External Control of Critical State Data](https://cwe.mitre.org/data/definitions/472.html) 