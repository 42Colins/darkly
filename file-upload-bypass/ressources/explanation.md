# 📤🔓 File Upload Bypass (Unrestricted File Upload)

> **OWASP Category:** A04:2021 – Insecure Design  
> **Severity:** 🔴 Critical  
> **Difficulty:** 🟡 Medium

The website has an image upload functionality at `/index.php?page=upload` that accepts image files. However, the application has multiple security flaws: weak file type validation that can be bypassed, and improper file path handling that allows attackers to upload malicious files to arbitrary locations on the server.

🎯 **Double Trouble:** This vulnerability combines weak validation with path traversal - a dangerous combination that can lead to Remote Code Execution!

---

## 🎯 Exploit Technique

### 🔧 Attack Evolution

#### 🥇 **First Attempt - Simple Bypass**
```bash
# Try uploading PHP file disguised as image
mv malicious.php malicious.jpeg
# Upload via web interface
# Result: File uploaded to /tmp but immediately deleted
```

#### 🥈 **Second Attempt - CURL with Path Traversal**
```bash
curl -X POST \
  -F "uploaded=@aaa.jpeg;filename=../../../../../../../../../../../../../var/aaa.php" \
  -F "Upload=Upload" \
  http://192.168.64.2/index.php\?page\=upload
```

**Exploitation breakdown:**
1. 🎭 **Content-Type Spoofing** - Tell server it's an image via CURL
2. 📁 **Path Traversal** - Use `../` sequences to escape intended directory
3. 🎯 **Target Directory** - Upload to `/var/` instead of `/tmp/`
4. 🔥 **Persistence** - File survives in permanent location
5. 🏆 **Success** - PHP code execution achieved

### 🌍 Attack Variations

| Method | Bypass Technique | Target |
|--------|------------------|--------|
| **🎭 Extension Spoofing** | `malicious.php.jpg` | Fool weak validation |
| **📄 MIME Type Manipulation** | Change Content-Type header | Bypass server-side checks |
| **🔧 Double Extension** | `shell.php.jpeg` | Confuse parsing logic |
| **📁 Path Traversal** | `../../../var/shell.php` | Escape upload directory |
| **🧬 Polyglot Files** | Valid image + PHP code | Bypass all validation |

---

## 🛠️ Security Implementation

### ❌ vs ✅ Comparison

| 🚫 **Vulnerable Implementation** | ✅ **Secure Implementation** |
|--------------------------------|----------------------------|
| Client-side file type checking | Server-side validation only |
| Extension-based validation | Magic number verification |
| User-controlled file paths | Fixed upload directory |
| Direct file execution | Sandboxed file storage |

### 🔒 Defense Strategies

**File Validation (Critical):**
- [ ] **🔍 Magic Number Check** - Verify actual file content, not just extension
- [ ] **📋 Whitelist Extensions** - Only allow specific, safe file types
- [ ] **📏 Size Limitations** - Implement reasonable file size limits
- [ ] **🧹 Filename Sanitization** - Remove dangerous characters and paths

**Upload Security:**
- [ ] **📁 Fixed Upload Directory** - Never use user input for file paths
- [ ] **🚫 Execution Prevention** - Store files outside web root
- [ ] **🔄 File Renaming** - Generate unique, safe filenames
- [ ] **🛡️ Content Scanning** - Scan for malicious content

**Advanced Protection:**
- [ ] **🏠 Sandboxing** - Isolate uploaded files
- [ ] **⏱️ Temporary Storage** - Auto-delete after processing
- [ ] **🔐 Access Controls** - Restrict file access permissions
- [ ] **📊 Monitoring** - Log all upload activities

**Secure Implementation Example:**
```php
function secure_upload($file) {
    // Validate file type by magic number
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    
    $allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($mime, $allowed)) {
        throw new Exception('Invalid file type');
    }
    
    // Generate safe filename
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    $filename = uniqid() . '.' . $ext;
    
    // Fixed, secure upload path
    $upload_path = '/var/secure_uploads/' . $filename;
    
    return move_uploaded_file($file['tmp_name'], $upload_path);
}
```

---

## ⚠️ Risk Assessment & Impact

### 🎭 Attack Scenarios by Severity

| Risk Level | Attack Vector | Business Impact | Example |
|------------|---------------|----------------|---------|
| 🔴 **Critical** | Remote Code Execution | Complete server compromise | PHP web shell upload |
| 🟠 **High** | Data Exfiltration | Sensitive data theft | Script to dump databases |
| 🟡 **Medium** | Defacement | Brand reputation damage | Malicious content injection |
| 🟢 **Low** | Resource Abuse | Server performance impact | Large file uploads |

### 🌍 Real-World Attack Examples

| Industry | Attack Scenario | Impact |
|----------|----------------|--------|
| 🏢 **Corporate** | Upload web shell via avatar | Complete network compromise |
| 🏥 **Healthcare** | Malicious file in patient portal | HIPAA violation, data breach |
| 🎓 **Education** | Student uploads backdoor | Access to academic records |
| 🛒 **E-commerce** | Shell via product image upload | Credit card data theft |

### 📈 Famous Security Incidents

#### 🏆 Hall of Shame
- **🏢 Fortune 500 Company (2018)**  
  *Vulnerability:* Unrestricted PHP upload in HR portal  
  *Impact:* 50,000+ employee records compromised  
  *Cost:* $25M+ in fines and remediation

- **🏥 Healthcare Provider (2020)**  
  *Vulnerability:* File upload bypass in patient portal  
  *Impact:* 2M+ medical records exposed  
  *Lesson:* Healthcare data is a prime target

- **🎮 Gaming Platform (2021)**  
  *Vulnerability:* Avatar upload allows web shell  
  *Impact:* Source code and user data stolen  
  *Fix:* Complete upload system redesign

---

## 🧠 Security Mindset

### 💭 Key Principles

> 🔐 **Golden Rule #1:** "Never trust file extensions - validate the actual content"

> 🕵️ **Golden Rule #2:** "Treat every upload as potentially malicious"

> 🛡️ **Golden Rule #3:** "Store uploads outside the web root whenever possible"

### 🎯 Developer Defense Tactics

| Principle | Implementation | Example |
|-----------|----------------|---------|
| **🔍 Content Validation** | Check file magic numbers | `89 50 4E 47` for PNG |
| **📁 Path Control** | Never use user input for paths | Fixed upload directories |
| **🚫 Execution Prevention** | Store outside web accessible areas | `/uploads/` not `/var/www/uploads/` |
| **🔄 File Processing** | Rename and sanitize all uploads | `uuid_v4().extension` |

---

## 🚨 Detection & Monitoring

### 🔍 Warning Signs
- Uploads with double extensions (`.php.jpg`)
- Files with executable extensions in image uploads
- Unusual file sizes or MIME types
- Path traversal patterns in filenames (`../`)
- Rapid succession of upload attempts

### 📊 Monitoring Implementation
```bash
# Monitor for suspicious upload patterns
tail -f /var/log/apache2/access.log | grep -E "(\.php|\.jsp|\.asp)" | grep upload

# Check for files with executable permissions in upload directory
find /var/uploads -type f -executable -ls

# Monitor file upload sizes and frequencies
awk '/upload/ {print $1, $7, $10}' /var/log/apache2/access.log | sort | uniq -c
```

---

## 🛡️ Testing & Validation

### 🔧 Penetration Testing Checklist
- [ ] Test various file extensions (`.php`, `.jsp`, `.asp`)
- [ ] Try double extensions (`.php.jpg`, `.asp.gif`)
- [ ] Attempt MIME type spoofing
- [ ] Test path traversal in filenames
- [ ] Upload polyglot files (image + code)
- [ ] Check for file execution in upload directory

### 🎯 Security Tools
- **🔥 Burp Suite** - File upload testing extensions
- **🕷️ OWASP ZAP** - Automated upload vulnerability scanning
- **🎯 Metasploit** - Web shell upload modules
- **🔍 Nikto** - Upload directory enumeration

---

## 🔗 Learning Resources

### 📚 Educational Materials
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [SANS Secure File Upload Guidelines](https://www.sans.org/white-papers/2172/)

### 🛠️ Practice Platforms
- **DVWA** - File upload vulnerabilities
- **WebGoat** - Malicious file upload lessons
- **Upload Labs** - Dedicated file upload challenges
- **HackTheBox** - Real-world upload bypass scenarios

### 🎯 Web Shell Collections
- **⚠️ Educational Only:**
  - PHP Web Shells (c99, r57, WSO)
  - ASP.NET Web Shells
  - JSP Web Shells

---

*Remember: A single uploaded file can compromise your entire server - validate everything! 📤🔒* 