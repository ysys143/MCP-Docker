# MCP OAuth2 Demo

A Python example that references Microsoft's [MCP for beginners OAuth2 demo](https://github.com/microsoft/mcp-for-beginners/tree/main/05-AdvancedTopics/mcp-oauth2-demo).

## 🎯 Overview

This project is a **minimal FastAPI application** that serves dual roles:

- **OAuth2 Authorization Server** (issuing JWT access tokens via client_credentials flow)
- **Resource Server** (protecting its own `/hello` endpoint)

## ✨ Key Features

### OAuth2 Authentication
- ✅ OAuth2 client_credentials flow
- ✅ JWT token generation and validation
- ✅ Protected MCP endpoints
- ✅ FastMCP authentication system integration
- ✅ OpenID Connect Discovery support
- ✅ JWKS endpoint

### 🔐 Enterprise Security Features
- ✅ **PII (Personally Identifiable Information) Detection & Masking**: Automatically identify and protect sensitive information
- ✅ **Data Encryption/Decryption**: Protect sensitive data using Fernet algorithm
- ✅ **Security Audit Logging**: Track all tool access and security events
- ✅ **Security Policy Enforcement**: Choose encryption, masking, or rejection when PII is detected
- ✅ **Integrated Security Architecture**: Complete integration of OAuth2 authentication with data protection

## 📁 Project Structure

```
oauth2-demo/
├── core/
│   ├── mcp_oauth2_server.py      # OAuth2 web server (FastAPI)
│   └── oauth2_common.py          # JWT token & authentication common logic
├── config/                       # Configuration files
├── docs/                         # Detailed documentation
├── keys/                         # JWT key storage
├── logs/                         # Security audit logs
├── security/                     # Security-related modules
└── tests/                        # Test files
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Using uv (recommended)
uv pip install fastapi uvicorn pyjwt python-jose[cryptography] fastmcp python-multipart httpx

# Or using pip
pip install fastapi uvicorn pyjwt python-jose[cryptography] fastmcp python-multipart httpx
```

### 2. Run Server

```bash
# Run OAuth2 web server
cd oauth2-demo
python core/mcp_oauth2_server.py

# Or use uvicorn directly
uvicorn core.mcp_oauth2_server:app --host 0.0.0.0 --port 8081
```

### 3. Test OAuth2 Flow

#### Get Token
```bash
curl -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access"
```

#### Call Protected Endpoint
```bash
# Use the token from above
curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" http://localhost:8081/hello
```

## 🔐 OAuth2 Setup & Testing

### 1. Verify Server Status

```bash
# Check OpenID Connect Discovery
curl http://localhost:8081/.well-known/openid-configuration

# Verify 401 Unauthorized (confirms security is enabled)
curl -v http://localhost:8081/
```

### 2. Token Acquisition & Validation

```bash
# Get token
TOKEN=$(curl -s -X POST http://localhost:8081/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=mcp-client&client_secret=secret&scope=mcp.access" \
  | jq -r .access_token)

# Access protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/hello
```

A successful response returning "MCP OAuth2 데모에서 안녕하세요!" confirms OAuth2 setup is working correctly.

## 🧪 Testing

### Automated Tests

```bash
# OAuth2 flow test
python tests/test_oauth2_demo.py

# Direct MCP tools test
python tests/test_mcp_tools_direct.py

# Integrated security test
python tests/test_mcp_integration.py
```

## 🛠️ MCP Tools Usage

### Available OAuth2 MCP Tools

- **`get_oauth2_server_status`**: Check OAuth2 server status
- **`create_oauth2_test_token`**: Generate test JWT token  
- **`get_oauth2_flow_guide`**: Provide OAuth2 flow guide
- **`validate_oauth2_setup`**: Validate complete OAuth2 setup

### Available Security MCP Tools

- **`test_pii_detection`**: Test PII detection and masking
- **`test_encryption`**: Test data encryption/decryption
- **`get_security_audit_log`**: View security audit logs
- **`simulate_data_breach_detection`**: Simulate data breach detection
- **`generate_security_report`**: Generate comprehensive security report

## 🔧 API Endpoints

### OAuth2 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth2/token` | POST | OAuth2 token issuance |
| `/.well-known/openid-configuration` | GET | OpenID Connect Discovery |
| `/.well-known/jwks.json` | GET | JSON Web Key Set |

### Protected Resources

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/` | GET | Server information | ✅ |
| `/hello` | GET | Greeting message | ✅ |

## ⚙️ Configuration

### Environment Variables

```bash
# JWT secret key (use strong key in production)
JWT_SECRET_KEY=mcp-oauth2-demo-secret-key-2025
```

### OAuth2 Client Credentials

- **Client ID**: `mcp-client`
- **Client Secret**: `secret`
- **Grant Type**: `client_credentials`
- **Scope**: `mcp.access`

> ⚠️ **Warning**: Use secure client secrets in production environments.

## 🔐 Security Features Usage

### PII Detection & Masking

```python
from security.security_common import get_pii_detector

pii_detector = get_pii_detector()

# PII detection
text = "Customer info: John Doe (john@example.com, 010-1234-5678)"
detected_pii = pii_detector.scan_text(text)
print(f"Detected PII: {detected_pii}")

# PII masking
masked_text = pii_detector.mask_pii(text)
print(f"Masked text: {masked_text}")
```

### Data Encryption

```python
from security.security_common import get_encryption_service

encryption_service = get_encryption_service()

# Encrypt sensitive data
sensitive_data = "Customer email: customer@company.com"
encrypted = encryption_service.encrypt(sensitive_data)

# Decrypt data
decrypted = encryption_service.decrypt(encrypted)
```

### Security Tool Decorator

```python
from security.security_common import secure_tool

@secure_tool(requires_encryption=True, log_access=True, pii_policy="encrypt")
async def process_customer_data(customer_info: str, client_id: str, user_id: str):
    # PII is automatically detected and encrypted
    # All access is logged in audit logs
    return {"status": "processed", "data": customer_info}
```

### Security Policy Options

- **`"encrypt"`**: Automatically encrypt when PII is detected (default)
- **`"mask"`**: Apply masking when PII is detected
- **`"reject"`**: Reject request when PII is detected

## 📊 Security Audit Logging

All security events are logged in `logs/security_audit.log` in JSON format:

```json
{
  "timestamp": "2025-01-06T12:34:56",
  "event_type": "tool_access",
  "tool_name": "store_sensitive_data",
  "user_id": "user123",
  "client_id": "mcp-client",
  "contains_pii": true,
  "action_taken": "executed_with_encryption"
}
```

## 🔍 Troubleshooting

### Common Issues

1. **401 Unauthorized**: 
   - Missing or invalid token
   - Check token expiration

2. **400 Bad Request**: 
   - Verify Content-Type is `application/x-www-form-urlencoded`
   - Check if required parameters are included

3. **Server Connection Failed**:
   ```bash
   # Check server status
   curl http://localhost:8081/.well-known/openid-configuration
   
   # Check Docker container status
   docker ps | grep oauth2
   ```

### Log Checking

```bash
# Security audit logs
tail -f oauth2-demo/logs/security_audit.log

# Docker container logs
docker logs mcp-oauth2-demo
```

## 📚 References

- [Microsoft MCP for beginners OAuth2 demo](https://github.com/microsoft/mcp-for-beginners/tree/main/05-AdvancedTopics/mcp-oauth2-demo)
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [FastAPI OAuth2 Documentation](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)

## 📄 License

This project is distributed under the MIT License.

## 🤝 Contributing

Please use GitHub Issues for bug reports or feature requests. 