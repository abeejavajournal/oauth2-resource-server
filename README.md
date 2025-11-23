# OAuth2 Resource Server - Complete Flow Demo

A production-ready Spring Boot application demonstrating OAuth2 Resource Server with JWT authentication.

## Architecture

```
┌──────────┐                                    ┌──────────────┐
│          │  1. Request Access Token          │              │
│  Client  │ ───────────────────────────────>  │  Keycloak    │
│  (curl)  │                                    │  (Port 8080) │
│          │  2. Return JWT Token               │              │
│          │ <───────────────────────────────  │  - Validates │
└──────────┘                                    │    user      │
     │                                          │  - Issues    │
     │ 3. Call API with Token                  │    JWT       │
     │    Authorization: Bearer <JWT>          └──────────────┘
     │                                                  │
     ▼                                                  │
┌──────────────────────────────────────┐              │
│  Resource Server (Port 8081)         │              │
│  ┌────────────────────────────────┐  │              │
│  │ 1. Extract JWT from Header     │  │              │
│  │ 2. Validate JWT Signature  ────┼──┼──────────────┘
│  │ 3. Check Expiration            │  │  (Fetch public keys)
│  │ 4. Verify Audience             │  │
│  │ 5. Extract Scopes/Roles        │  │
│  │ 6. Authorize Request           │  │
│  └────────────────────────────────┘  │
│                                       │
│  ┌────────────────────────────────┐  │
│  │ Protected Endpoints:           │  │
│  │ • GET  /api/resources          │  │ Requires: SCOPE_read
│  │ • POST /api/resources          │  │ Requires: SCOPE_write
│  │ • DELETE /api/resources/{id}   │  │ Requires: SCOPE_admin
│  │ • GET  /api/resources/admin    │  │ Requires: ROLE_ADMIN
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

##  Quick Start

### 1. Start Keycloak OAuth2 Server
```bash
docker-compose up -d keycloak
```
Wait 30 seconds for startup. Access at: http://localhost:8080

### 2. Start Resource Server
```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
mvn spring-boot:run
```
Runs on: http://localhost:8081

## Complete OAuth2 Flow

### Step 1: Get Access Token
```bash
# Get token for regular user (read/write scopes)
curl -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-client-secret" \
  -d "username=testuser" \
  -d "password=password123" \
  -d "scope=openid read write"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "scope": "openid read write"
}
```

### Step 2: Use Token to Access Protected Resources
```bash
# Save your token
export TOKEN="your_access_token_here"

# Call protected endpoint
curl http://localhost:8081/api/resources \
  -H "Authorization: Bearer $TOKEN"
```

**What Happens Behind the Scenes:**
1. **Client sends request** with JWT in Authorization header
2. **Resource Server extracts JWT** from `Bearer` token
3. **Validates signature** using Keycloak's public keys
4. **Checks expiration** time
5. **Verifies audience** matches `api://default`
6. **Extracts scopes** from JWT claims (`SCOPE_read`, `SCOPE_write`, etc.)
7. **Authorizes request** based on required scopes
8. **Returns response** if authorized, 403 if forbidden

## Test Users

| Username | Password | Scopes | Description |
|----------|----------|--------|-------------|
| testuser | password123 | read, write | Regular user |
| admin | admin123 | read, write, admin | Admin user with all scopes |

## API Endpoints

| Endpoint | Method | Required Scope/Role | Description |
|----------|--------|-------------------|-------------|
| `/api/resources/public` | GET | None | Public endpoint |
| `/api/resources` | GET | `SCOPE_read` | List resources |
| `/api/resources` | POST | `SCOPE_write` | Create resource |
| `/api/resources/{id}` | DELETE | `SCOPE_admin` | Delete resource |
| `/api/resources/admin` | GET | `ROLE_ADMIN` | Admin endpoint |
| `/api/resources/authenticated` | GET | Any authenticated | User info |
| `/api/resources/debug/jwt` | GET | `SCOPE_read` | View JWT claims |

## Example Requests

### Public Endpoint (No Auth)
```bash
curl http://localhost:8081/api/resources/public
```

### Get Resources (Requires read scope)
```bash
curl http://localhost:8081/api/resources \
  -H "Authorization: Bearer $TOKEN"
```

### Create Resource (Requires write scope)
```bash
curl -X POST http://localhost:8081/api/resources \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Resource",
    "description": "Created via API",
    "type": "TEST",
    "ownerId": "testuser"
  }'
```

### Delete Resource (Requires admin scope)
```bash
curl -X DELETE http://localhost:8081/api/resources/123 \
  -H "Authorization: Bearer $TOKEN"
```

### View Your JWT Claims
```bash
curl http://localhost:8081/api/resources/debug/jwt \
  -H "Authorization: Bearer $TOKEN"
```

## Understanding the JWT Token

Decode your token at https://jwt.io to see:

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id"
}
```

**Payload:**
```json
{
  "sub": "testuser",
  "aud": "api://default",
  "scope": "openid read write",
  "iss": "http://localhost:8080/realms/demo",
  "exp": 1234567890,
  "iat": 1234564290,
  "email": "testuser@example.com"
}
```

**Verification:**
- Signature is verified using Keycloak's public key
- Ensures token hasn't been tampered with
- Validates issuer, audience, and expiration

## Quick Commands

```bash
# View Keycloak logs
docker-compose logs -f keycloak

# Stop all services
docker-compose down

# Restart services
docker-compose restart

# Run interactive test script
./test-api.sh
```

## Complete Test Flow

```bash
# 1. Start services
docker-compose up -d keycloak
mvn spring-boot:run

# 2. Get token
TOKEN=$(curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=demo-client" \
  -d "client_secret=demo-client-secret" \
  -d "username=testuser" \
  -d "password=password123" \
  -d "scope=openid read write" | jq -r '.access_token')

# 3. Use token
curl http://localhost:8081/api/resources \
  -H "Authorization: Bearer $TOKEN"

# 4. Try unauthorized action (should fail with 403)
curl -X DELETE http://localhost:8081/api/resources/123 \
  -H "Authorization: Bearer $TOKEN"
```

## Key Security Features

- **JWT Signature Validation** - Ensures token authenticity
- **Expiration Checking** - Tokens expire after 1 hour
- **Audience Validation** - Tokens must be intended for this API
- **Scope-based Authorization** - Fine-grained access control
- **Role-based Authorization** - Role hierarchy support
- **Stateless Authentication** - No server-side sessions needed

## Learn More

- **Keycloak Admin Console**: http://localhost:8080/admin (admin/admin)
- **Application Health**: http://localhost:8081/api/actuator/health
- **JWT Decoder**: https://jwt.io

---

Built Spring Boot 3.2.0, Spring Security 6.2.0, and Keycloak 23.0
