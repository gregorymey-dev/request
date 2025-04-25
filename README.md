# request-secure

A fork of the popular `request` library with security fixes for SSRF and prototype pollution vulnerabilities.

## Background

The original [request](https://github.com/request/request) package has been deprecated, but it's still widely used. This fork addresses two significant security vulnerabilities:

1. **Server-side Request Forgery (SSRF)** - A medium severity vulnerability (SNYK-JS-REQUEST-3361831) that could allow attackers to make requests to internal resources.
2. **Prototype Pollution** - A medium severity vulnerability (SNYK-JS-TOUGHCOOKIE-5672873) in the tough-cookie dependency.

## Installation

```bash
npm install request-secure
```

## Usage

Use it exactly like the original `request` package:

```javascript
const request = require('request-secure');

request('https://www.google.com', (error, response, body) => {
  if (error) console.error('Error:', error);
  console.log('Status code:', response.statusCode);
  console.log('Body:', body);
});
```

## Security Enhancements

### 1. SSRF Protection

By default, this fork prevents requests to:
- Private IP ranges (10.0.0.0/8, 192.168.0.0/16, etc.)
- Localhost (127.0.0.1, localhost)
- Link-local addresses (169.254.0.0/16)
- Restricted protocols (only http: and https: are allowed by default)

#### Configuring SSRF Protection

You can disable SSRF protection for specific requests:

```javascript
request({
  url: 'http://192.168.1.1',
  disableSSRFProtection: true
}, callback);
```

To customize SSRF protection globally:

```javascript
const request = require('request-secure');
const ssrfProtection = require('request-secure/lib/ssrf-protection');

// Create custom middleware with your configuration
const customConfig = {
  allowPrivateIPs: true,                 // Allow private IPs (not recommended in production)
  allowLocalhostDomains: true,           // Allow localhost domains
  blockedHosts: ['evil.com', 'attacker.net'], // Block specific hosts
  allowedProtocols: ['http:', 'https:', 'ftp:'] // Allow additional protocols
};

// Apply custom configuration
request.defaults({
  ssrfConfig: customConfig
});
```

### 2. Fixed Prototype Pollution

We've updated tough-cookie to version 4.1.3, which fixes the prototype pollution vulnerability. A compatibility layer maintains backward compatibility with request's API.

## Backward Compatibility

This fork strives to maintain 100% backward compatibility with the original request package. If you encounter any compatibility issues, please [open an issue](https://github.com/your-username/request-secure/issues).

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Apache-2.0 (same as the original request package)