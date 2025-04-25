// ssrf-protection.js
// Utility to prevent SSRF attacks in the request library

'use strict';

const url = require('url');
const net = require('net');
const ipaddr = require('ipaddr.js');

/**
 * Default blocklist of private IP ranges
 */
const DEFAULT_BLOCKED_RANGES = [
  // IPv4 private ranges
  '10.0.0.0/8',       // Private network - RFC 1918
  '172.16.0.0/12',    // Private network - RFC 1918
  '192.168.0.0/16',   // Private network - RFC 1918
  '127.0.0.0/8',      // Localhost - RFC 1122
  '169.254.0.0/16',   // Link local - RFC 3927
  '192.0.2.0/24',     // TEST-NET - RFC 5737
  '198.51.100.0/24',  // TEST-NET - RFC 5737
  '203.0.113.0/24',   // TEST-NET - RFC 5737
  '224.0.0.0/4',      // Multicast - RFC 5771
  '240.0.0.0/4',      // Reserved - RFC 1112
  '0.0.0.0/8',        // Current network

  // IPv6 private ranges
  '::/128',           // Unspecified address
  '::1/128',          // Localhost
  'fc00::/7',         // Unique local address
  'fe80::/10',        // Link local address
  'ff00::/8',         // Multicast
];

/**
 * Default allowed protocols
 */
const DEFAULT_ALLOWED_PROTOCOLS = ['http:', 'https:'];

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  allowPrivateIPs: false,
  blockedRanges: DEFAULT_BLOCKED_RANGES,
  allowedProtocols: DEFAULT_ALLOWED_PROTOCOLS,
  allowLocalhostDomains: false,
  blockedHosts: [
    'localhost',
    '0.0.0.0',
    '127.0.0.1',
    '::1'
  ]
};

/**
 * Parse CIDR notation to check if IP is in range
 */
function isIPInRange(ip, cidr) {
  try {
    const addr = ipaddr.parse(ip);
    const range = ipaddr.parseCIDR(cidr);
    return addr.match(range);
  } catch (e) {
    return false;
  }
}

/**
 * Check if a hostname resolves to a private IP address
 */
async function isPrivateHost(hostname) {
  return new Promise((resolve) => {
    try {
      const dns = require('dns');
      dns.lookup(hostname, (err, address) => {
        if (err || !address) {
          return resolve(false);
        }
        
        // Check if the resolved IP is in any blocked range
        const isBlocked = DEFAULT_BLOCKED_RANGES.some(range => 
          isIPInRange(address, range)
        );
        
        resolve(isBlocked);
      });
    } catch (e) {
      resolve(false);
    }
  });
}

/**
 * Validate if a URL is safe from SSRF attacks
 */
async function validateUrl(inputUrl, config = {}) {
  // Merge with default config
  const options = { ...DEFAULT_CONFIG, ...config };
  
  // Basic validation
  if (!inputUrl || typeof inputUrl !== 'string') {
    throw new Error('Invalid URL');
  }

  // Parse URL
  let parsedUrl;
  try {
    parsedUrl = new URL(inputUrl);
  } catch (e) {
    throw new Error('Invalid URL format');
  }

  // Protocol check
  if (!options.allowedProtocols.includes(parsedUrl.protocol)) {
    throw new Error(`Protocol not allowed: ${parsedUrl.protocol}`);
  }

  // Hostname checks
  const hostname = parsedUrl.hostname.toLowerCase();
  
  // Check against blocklisted hosts
  if (options.blockedHosts.includes(hostname)) {
    throw new Error(`Hostname blocked: ${hostname}`);
  }
  
  // Check localhost domains
  if (!options.allowLocalhostDomains) {
    if (hostname === 'localhost' || 
        hostname.endsWith('.localhost') || 
        hostname.endsWith('.local')) {
      throw new Error(`Localhost domain not allowed: ${hostname}`);
    }
  }
  
  // IP validation
  const isIP = net.isIP(hostname);
  if (isIP) {
    // If it's an IP address, check if it's in a blocked range
    if (!options.allowPrivateIPs) {
      const isBlocked = options.blockedRanges.some(range => 
        isIPInRange(hostname, range)
      );
      
      if (isBlocked) {
        throw new Error(`IP address in blocked range: ${hostname}`);
      }
    }
  } else {
    // If it's a hostname, check if it resolves to a private IP
    if (!options.allowPrivateIPs) {
      const isPrivate = await isPrivateHost(hostname);
      if (isPrivate) {
        throw new Error(`Hostname resolves to private IP: ${hostname}`);
      }
    }
  }
  
  return true;
}

/**
 * Create middleware to use within request
 */
function createSSRFProtection(userConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  
  return async function ssrfProtectionMiddleware(options) {
    // Skip validation if explicitly configured to do so
    if (options.skipSSRFCheck === true) {
      return options;
    }

    let urlToCheck = options.url || options.uri;
    
    // Handle when url is an object
    if (typeof urlToCheck === 'object' && urlToCheck !== null) {
      urlToCheck = url.format(urlToCheck);
    }
    
    await validateUrl(urlToCheck, config);
    return options;
  };
}

module.exports = {
  validateUrl,
  createSSRFProtection,
  DEFAULT_CONFIG
};