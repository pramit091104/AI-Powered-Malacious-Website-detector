/**
 * Extracts cybersecurity features from a given URL.
 */
export interface URLFeatures {
  urlLength: number;
  dotCount: number;
  subdomainCount: number;
  hasIP: number;
  isHTTPS: number;
  suspiciousKeywordCount: number;
  specialCharCount: number;
  hyphenCount: number;
  domainLength: number;
  redirectCount: number; // Simulated as we don't fetch the URL here
  digitCount: number;
  isShortener: number;
}

export const extractFeatures = (url: string): URLFeatures => {
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith('http')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let urlObj: URL;
  try {
    urlObj = new URL(cleanUrl);
  } catch (e) {
    // Fallback for malformed URLs
    return {
      urlLength: cleanUrl.length,
      dotCount: (cleanUrl.match(/\./g) || []).length,
      subdomainCount: 0,
      hasIP: 0,
      isHTTPS: 0,
      suspiciousKeywordCount: 0,
      specialCharCount: 0,
      hyphenCount: 0,
      domainLength: 0,
      redirectCount: 0,
      digitCount: 0,
      isShortener: 0,
    };
  }

  const hostname = urlObj.hostname;
  const path = urlObj.pathname + urlObj.search;

  // 1. URL Length
  const urlLength = cleanUrl.length;

  // 2. Dot Count
  const dotCount = (cleanUrl.match(/\./g) || []).length;

  // 3. Subdomain Count
  const subdomains = hostname.split('.');
  const subdomainCount = subdomains.length > 2 ? subdomains.length - 2 : 0;

  // 4. Presence of IP Address
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hasIP = ipRegex.test(hostname) ? 1 : 0;

  // 5. HTTPS Usage
  const isHTTPS = urlObj.protocol === 'https:' ? 1 : 0;

  // 6. Suspicious Keywords
  const suspiciousKeywords = ['login', 'secure', 'verify', 'update', 'account', 'banking', 'paypal', 'signin', 'confirm'];
  const suspiciousKeywordCount = suspiciousKeywords.reduce((count, kw) => {
    return count + (cleanUrl.toLowerCase().includes(kw) ? 1 : 0);
  }, 0);

  // 7. Special Characters
  const specialChars = ['@', '?', '&', '=', '_', '~'];
  const specialCharCount = specialChars.reduce((count, char) => {
    return count + (cleanUrl.split(char).length - 1);
  }, 0);

  // 8. Hyphen Count
  const hyphenCount = (cleanUrl.match(/-/g) || []).length;

  // 9. Domain Length
  const domainLength = hostname.length;

  // 10. Redirect Count (Simulated)
  // In a real production system, we'd follow redirects.
  // Here we check for multiple 'http' or 'https' in the URL string which often indicates redirection chains.
  const redirectCount = (cleanUrl.match(/http/gi) || []).length - 1;

  // 11. Digit Count
  const digitCount = (cleanUrl.match(/\d/g) || []).length;

  // 12. Shortener usage
  const shorteners = ['bit.ly', 'goo.gl', 't.co', 'is.gd', 'tinyurl.com', 'tr.im', 'v.gd', 'snipurl.com', 'shorte.st', 'ow.ly'];
  const isShortener = shorteners.some(s => hostname.includes(s)) ? 1 : 0;

  return {
    urlLength,
    dotCount,
    subdomainCount,
    hasIP,
    isHTTPS,
    suspiciousKeywordCount,
    specialCharCount,
    hyphenCount,
    domainLength,
    redirectCount,
    digitCount,
    isShortener,
  };
};
