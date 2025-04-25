// tough-cookie-compatibility.js
// This adapter ensures compatibility between tough-cookie 2.x API used in request
// and the newer tough-cookie 4.x API

'use strict';

const toughCookie = require('tough-cookie');

// Check if we're using the new API
const isNewAPI = typeof toughCookie.CookieJar.deserializeSync === 'function';

// Create compatibility layer if using tough-cookie 4.x
if (isNewAPI) {
  // In 4.x, some methods have been renamed or behavior changed
  const originalJar = toughCookie.CookieJar;
  
  // Override methods that have changed signature or behavior
  const originalGetCookieString = originalJar.prototype.getCookieString;
  originalJar.prototype.getCookieString = function(url, options, cb) {
    // Handle both callback and promise-based API
    if (typeof options === 'function') {
      cb = options;
      options = {};
    }
    
    if (typeof cb === 'function') {
      return originalGetCookieString.call(this, url, options, cb);
    } else {
      return originalGetCookieString.call(this, url, options);
    }
  };
  
  // Add back compatibility for other methods if needed
  // ...
}

module.exports = toughCookie;