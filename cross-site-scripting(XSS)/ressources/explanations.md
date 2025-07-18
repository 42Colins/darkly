# XSS with Base64 Encoding Attack - Complete Explanation
## What is this attack?
This is a **Cross-Site Scripting (XSS)** attack that uses **Base64 encoding** to bypass input filters and security mechanisms.

## Attack Components
### 1. Cross-Site Scripting (XSS)
* **Definition**: Injecting malicious scripts into web pages viewed by other users
* **Goal**: Execute JavaScript in the victim's browser
* **Impact**: Steal cookies, session hijacking, data theft, defacement
### 2. Base64 Encoding Bypass
* **Purpose:** Obfuscate the payload to evade detection
* **How it works:** Encode malicious script in Base64 to bypass input filters
* **Advantage:** Many filters don't decode Base64 before checking content
## Step-by-Step Attack Process
### Step 1: Identify the Vulnerability
    Target: http://10.13.200.175/index.php?page=media&src=...
* The `src` parameter appears to be vulnerable to injection
* The application processes user input without proper sanitization
### Step 2: Craft the Basic Payload

    <script>alert('XSS')</script>

* This is our malicious JavaScript code
* `alert()` is used for proof-of-concept (in real attacks, this would be more malicious)

### Step 3: Encode the Payload

    Original: <script>alert('XSS')</script>
    Base64:   PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
* Base64 encoding obfuscates the malicious content
* Makes it harder for filters to detect the script tags
### Step 4: Delivery Methods
Data URI with Base64:

    http://10.13.200.175/index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=

## How the Attack Works
### 1. User Input Processing
    User sends: src=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=
### 2. Server Processing
* Server receives the Base64 encoded data
* If vulnerable, it processes the data URI
* Decodes the Base64 content
Renders it as HTML
### 3. Browser Execution
* Browser receives: `<script>alert('XSS')</script>`
* Executes the JavaScript code
* Alert box appears (proof of successful XSS)
## Why This Attack Works
### 1. Input Validation Bypass
* Many filters only check for obvious script tags
* Base64 encoding hides the malicious content
* Data URIs are often overlooked by security filters
### 2. Trust in Data URIs
* Browsers trust data URIs as legitimate content
* Applications may not validate data URI contents
* Base64 decoding happens automatically
### 3. Insufficient Output Encoding
* Application doesn't properly encode output
* User input is reflected directly in the response
* No Content Security Policy (CSP) to block inline scripts

## Real-World Impact
In production environments, this type of attack could:

* Steal user credentials
* Hijack user sessions
* Deface websites
* Distribute malware
* Perform actions on behalf of users
