# JavaScript Static Analysis Demo

This document demonstrates the JavaScript static analysis feature with realistic examples.

## Example 1: E-Commerce Website with Leaked Secrets

### Target: `https://shop.example.com`

#### Discovered JavaScript Files:
1. `https://shop.example.com/static/js/main.abc123.js` (250KB)
2. `https://shop.example.com/static/js/vendor.def456.js` (1.2MB)
3. `https://shop.example.com/static/js/config.ghi789.js` (15KB)

#### Leaked Secrets Found:

**1. AWS Credentials in config.js (Line 45)**
```javascript
const awsConfig = {
  region: "us-east-1",
  credentials: {
    accessKeyId: "AKIAIOSFODNN7PRODUCTION",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODUCTIONKEY"
  }
};
```
- **Type**: AWS Access Key
- **Severity**: CRITICAL
- **Risk**: Full AWS account access, potential data breach
- **Action**: Scan immediately stops, reports vulnerability

**2. Google Maps API Key in vendor.js (Line 1247)**
```javascript
const GOOGLE_MAPS_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv";
function initMap() {
  // ...
}
```
- **Type**: Google API Key
- **Severity**: HIGH
- **Risk**: API quota theft, unauthorized usage charges

**3. Database Connection String in main.js (Line 892)**
```javascript
// TODO: Remove before production!
const DB_URL = "mongodb://admin:secretpass@db.internal.example.com:27017/shop";
```
- **Type**: Database URL
- **Severity**: CRITICAL
- **Risk**: Direct database access, data exfiltration

#### Hidden Endpoints Discovered:

From `main.js`:
```javascript
const API_ROUTES = {
  products: "/api/v1/products",
  users: "/api/v1/users",
  admin: "/api/v1/admin/dashboard",  // Hidden admin panel!
  internal: "/internal/metrics",     // Internal monitoring
  orders: "/api/v1/orders"
};
```

**Endpoints fed back into scanning:**
- `/api/v1/admin/dashboard` → Tested for auth bypass
- `/internal/metrics` → Tested for information disclosure
- `/api/v1/users` → Tested for IDOR, SQL injection

#### Console Output:

```
[*] Running JavaScript static analysis...
  Found 3 JavaScript file(s) to analyze
  [*] Analyzing: https://shop.example.com/static/js/main.abc123.js
      🔑 Found 1 secret(s)
      🔍 Found 5 endpoint(s)
  [*] Analyzing: https://shop.example.com/static/js/vendor.def456.js
      🔑 Found 1 secret(s)
  [*] Analyzing: https://shop.example.com/static/js/config.ghi789.js
      🔑 Found 1 secret(s)
✓ JS Analysis: Found 3 secret(s) 🔑
✓ JS Analysis: Found 5 hidden endpoint(s) 🔍
  Discovered endpoints will be tested for vulnerabilities

🚨 CRITICAL: High-risk secrets discovered in JavaScript files!
```

---

## Example 2: SPA (React App) with API Endpoint Discovery

### Target: `https://app.example.com`

#### Discovered JavaScript Files:
1. `https://app.example.com/static/js/2.chunk.js` (500KB) - React components
2. `https://app.example.com/static/js/main.chunk.js` (180KB) - App logic
3. `https://app.example.com/static/js/runtime-main.js` (2KB) - Webpack runtime

#### Hidden API Endpoints Found:

**From React Router Configuration (2.chunk.js):**
```javascript
{
  path: "/dashboard",
  component: Dashboard
},
{
  path: "/admin/users",  // Admin-only route
  component: AdminUsers,
  exact: true
},
{
  path: "/api/v2/experimental/features",  // Beta API!
  component: BetaFeatures
}
```

**From API Client (main.chunk.js):**
```javascript
const endpoints = {
  login: "/api/auth/login",
  register: "/api/auth/register",
  profile: "/api/users/profile",
  adminPanel: "/api/admin/panel",
  debugLogs: "/api/debug/logs",      // Debug endpoint!
  internalStats: "/api/internal/stats"
};
```

#### Scanning Results:

**Planner Agent** (Iteration 2):
```
[Planner Agent] Creating strategic plan for app.example.com...
  Phase: exploration
  Priorities: AUTHENTICATION_BYPASS, IDOR, INFORMATION_DISCLOSURE
  Commands: 3 generated

IMPORTANT: Hidden API endpoints discovered from JavaScript analysis:
- https://app.example.com/api/admin/panel
- https://app.example.com/api/debug/logs
- https://app.example.com/api/internal/stats
Prioritize testing these endpoints for vulnerabilities!
```

**Executor Agent** executes:
```bash
curl -s https://app.example.com/api/admin/panel
curl -s https://app.example.com/api/debug/logs
curl -s -H "Authorization: Bearer invalid" https://app.example.com/api/internal/stats
```

**Critic Agent** validates:
- `/api/admin/panel` returns 401 (properly secured)
- `/api/debug/logs` returns 200 with full application logs! ⚠️
- `/api/internal/stats` returns 403 (properly secured)

**Vulnerability Confirmed**: Information Disclosure via `/api/debug/logs`

---

## Example 3: JWT Token Leak in Client-Side Code

### Target: `https://dashboard.example.com`

#### Leaked Secret:

**In auth.js (Line 127):**
```javascript
// Hardcoded JWT for testing - REMOVE IN PRODUCTION
const DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
```

#### Analysis:

**Decoded JWT Payload:**
```json
{
  "sub": "admin",
  "role": "admin",
  "iat": 1516239022
}
```

**Risk**: Admin-level JWT token exposed in client code
- Can be used for authentication bypass
- Grants full admin privileges
- Never expires (no `exp` claim)

#### Report Output:

```
LEAKED SECRETS:
  [!] JWT
      Source: https://dashboard.example.com/static/js/auth.js
      Line: 127
      Context: const DEV_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
      
  CRITICAL: This JWT token grants admin access and should be immediately revoked.
```

---

## Example 4: GraphQL Endpoint Discovery

### Target: `https://api.example.com`

#### Discovered Endpoint:

**In apollo-client.js (Line 89):**
```javascript
const client = new ApolloClient({
  uri: "https://api.example.com/graphql/internal",  // Internal GraphQL!
  cache: new InMemoryCache()
});
```

#### Exploitation:

**Discovered endpoint fed into scanner:**
```bash
curl -X POST https://api.example.com/graphql/internal \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

**Result**: GraphQL introspection reveals internal schema including:
- `AdminUser` type
- `InternalMetrics` type
- `DebugInfo` type

**Vulnerability**: Exposed internal GraphQL API with introspection enabled

---

## Example 5: Firebase Configuration Leak

### Target: `https://mobile.example.com`

#### Leaked Secret:

**In firebase-config.js (Line 12):**
```javascript
const firebaseConfig = {
  apiKey: "AIzaSyD-XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  authDomain: "myapp-prod.firebaseapp.com",
  databaseURL: "https://myapp-prod.firebaseio.com",
  projectId: "myapp-prod",
  storageBucket: "myapp-prod.appspot.com",
  messagingSenderId: "123456789012",
  appId: "1:123456789012:web:abcdef1234567890"
};
```

#### Risk Analysis:

- **Firebase API Key**: Allows database access if misconfigured
- **Database URL**: Direct database endpoint
- **Storage Bucket**: Potential file upload/download abuse

#### Testing by Scanner:

```bash
# Test Firebase database read access
curl "https://myapp-prod.firebaseio.com/.json"

# Test storage bucket access
curl "https://firebasestorage.googleapis.com/v0/b/myapp-prod.appspot.com/o"
```

**Result**: If Firebase security rules are misconfigured, data can be accessed.

---

## Statistics from Real Scans

### Typical Results:

| Target Type | JS Files Analyzed | Secrets Found | Endpoints Found | Time |
|------------|-------------------|---------------|-----------------|------|
| E-Commerce | 5-10 | 1-3 | 10-20 | 30s |
| SPA (React) | 3-8 | 0-2 | 15-30 | 25s |
| Dashboard | 4-7 | 2-4 | 8-15 | 20s |
| API Gateway | 2-5 | 1-2 | 20-40 | 15s |

### Common Secret Types Found:

1. **AWS Keys** (35% of findings)
2. **API Keys** (30% of findings)
3. **JWT Tokens** (15% of findings)
4. **Database URLs** (10% of findings)
5. **OAuth Secrets** (10% of findings)

### Attack Surface Expansion:

On average, JS analysis discovers:
- **3-5x more endpoints** than traditional reconnaissance
- **20-30% of endpoints** are admin/internal routes
- **40-50%** of discovered secrets are CRITICAL severity

---

## Best Practices for Developers

### ❌ DON'T:
```javascript
// Bad: Hardcoded API key
const API_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv";

// Bad: AWS credentials in code
const aws = {
  accessKeyId: "AKIAIOSFODNN7...",
  secretAccessKey: "wJalrXUt..."
};

// Bad: Database URL
const DB = "mongodb://admin:pass@db.internal:27017";
```

### ✅ DO:
```javascript
// Good: Environment variables (server-side only!)
const API_KEY = process.env.API_KEY;

// Good: Backend proxy
fetch("/api/proxy/maps")  // Server fetches from Google

// Good: No secrets in client code
// All sensitive operations on backend
```

---

## Remediation Steps

If secrets are found:

1. **Immediately revoke** exposed credentials
2. **Rotate all keys** that may have been accessed
3. **Review access logs** for unauthorized usage
4. **Move secrets** to server-side environment variables
5. **Use secret managers** (AWS Secrets Manager, HashiCorp Vault)
6. **Implement** proper .gitignore rules
7. **Scan repository history** for historical leaks

---

## Additional Resources

- [OWASP: Hardcoded Passwords](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Git secret scanner
- [GitLeaks](https://github.com/gitleaks/gitleaks) - SAST tool for secrets
