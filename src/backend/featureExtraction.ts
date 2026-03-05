import axios from 'axios';
import * as cheerio from 'cheerio';

// Helper function for obfuscation detection
function detectObfuscation(url: string): { hasObfuscation: boolean; count: number; ratio: number } {
    let obfuscatedChars = 0;
    
    const encodedMatches = url.match(/%[0-9A-Fa-f]{2}/g) || [];
    obfuscatedChars += encodedMatches.length;
    
    const unicodeMatches = url.match(/\\u[0-9A-Fa-f]{4}/g) || [];
    obfuscatedChars += unicodeMatches.length;
    
    const hexMatches = url.match(/0x[0-9A-Fa-f]+/g) || [];
    obfuscatedChars += hexMatches.length;
    
    const base64Pattern = /[A-Za-z0-9+\/]{20,}={0,2}/g;
    const base64Matches = url.match(base64Pattern) || [];
    obfuscatedChars += base64Matches.length * 5;
    
    const ratio = obfuscatedChars / url.length;
    
    return {
        hasObfuscation: obfuscatedChars > 0,
        count: obfuscatedChars,
        ratio: ratio
    };
}

// Helper function for suspicious pattern detection
function detectSuspiciousPatterns(url: string): { score: number; patterns: string[] } {
    const patterns: string[] = [];
    let score = 0;
    
    const urlLower = url.toLowerCase();
    
    const hyphenCount = (url.match(/-/g) || []).length;
    if (hyphenCount > 3) {
        score += 0.10;
        patterns.push(`Multiple hyphens (${hyphenCount})`);
    }
    
    if (url.includes('@')) {
        score += 0.25;
        patterns.push('@ symbol in URL');
    }
    
    if (url.split('//').length > 2) {
        score += 0.15;
        patterns.push('Double slashes in path');
    }
    
    const suspiciousInUrl = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm'];
    for (const keyword of suspiciousInUrl) {
        if (urlLower.includes(keyword)) {
            score += 0.08;
            patterns.push(`Suspicious keyword: "${keyword}"`);
        }
    }
    
    if (url.match(/:\d{2,5}\//)) {
        score += 0.12;
        patterns.push('Non-standard port');
    }
    
    const dotCount = (url.match(/\./g) || []).length;
    if (dotCount > 5) {
        score += 0.10;
        patterns.push(`Excessive dots (${dotCount})`);
    }
    
    return { score: Math.min(1, score), patterns };
}

/**
 * Dynamically extracts all 50+ features from a live URL using axios and cheerio.
 * Enhanced with advanced phishing detection capabilities.
 */
export const extractFeaturesAsync = async (url: string) => {
  const features: any = {};
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith('http')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let urlObj;
  try {
    urlObj = new URL(cleanUrl);
  } catch (e) {
    urlObj = new URL('http://malformed.internal');
  }

  const hostname = urlObj.hostname;

  // Basic String Features
  features.URLLength = cleanUrl.length;
  features.DomainLength = hostname.length;
  features.IsDomainIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) ? 1 : 0;
  features.IsHTTPS = urlObj.protocol === 'https:' ? 1 : 0;

  const tlds = hostname.split('.');
  features.TLDLength = tlds.length > 1 ? tlds[tlds.length - 1].length : 0;
  features.NoOfSubDomain = tlds.length > 2 ? tlds.length - 2 : 0;

  // Character Counts
  features.NoOfLettersInURL = (cleanUrl.match(/[a-zA-Z]/g) || []).length;
  features.LetterRatioInURL = features.NoOfLettersInURL / features.URLLength;
  features.NoOfDegitsInURL = (cleanUrl.match(/\d/g) || []).length;
  features.DegitRatioInURL = features.NoOfDegitsInURL / features.URLLength;
  features.NoOfEqualsInURL = (cleanUrl.match(/=/g) || []).length;
  features.NoOfQMarkInURL = (cleanUrl.match(/\?/g) || []).length;
  features.NoOfAmpersandInURL = (cleanUrl.match(/&/g) || []).length;

  const specialChars = (cleanUrl.match(/[^a-zA-Z0-9]/g) || []).length;
  features.NoOfOtherSpecialCharsInURL = specialChars - (features.NoOfEqualsInURL + features.NoOfQMarkInURL + features.NoOfAmpersandInURL);
  features.SpacialCharRatioInURL = specialChars / features.URLLength;

  // Advanced URL Pattern Detection
  const suspiciousPatterns = detectSuspiciousPatterns(cleanUrl);
  features.SuspiciousPatternScore = suspiciousPatterns.score;
  features.SuspiciousPatternCount = suspiciousPatterns.patterns.length;

  // Obfuscation Detection (Enhanced)
  const obfuscationCheck = detectObfuscation(cleanUrl);
  features.HasObfuscation = obfuscationCheck.hasObfuscation ? 1 : 0;
  features.NoOfObfuscatedChar = obfuscationCheck.count;
  features.ObfuscationRatio = obfuscationCheck.ratio;

  // These complex heuristics require the original dataset's NLP pipeline to compute.
  // We leave them undefined so the predictor can substitute the dataset mean,
  // effectively neutralizing them (z-score of mean = 0 = no influence).
  // features.URLSimilarityIndex  — will be filled by predictor
  // features.CharContinuationRate — will be filled by predictor
  // features.TLDLegitimateProb   — will be filled by predictor
  // features.URLCharProb         — will be filled by predictor

  // Web Scraping Features
  let html = ''; // Declare html outside try block for later use
  try {
    const response = await axios.get(cleanUrl, {
      timeout: 5000,
      maxRedirects: 5,
      validateStatus: () => true // Resolve on any status code
    });

    const finalUrl = response.request.res.responseUrl || cleanUrl;
    features.NoOfURLRedirect = finalUrl !== cleanUrl ? 1 : 0;
    features.NoOfSelfRedirect = 0;

    html = typeof response.data === 'string' ? response.data : '';
    const $ = cheerio.load(html);

    // HTML Structure Features
    const lines = html.split('\n');
    features.LineOfCode = lines.length;
    features.LargestLineLength = Math.max(...lines.map(l => l.length), 0);

    const title = $('title').text() || '';
    features.HasTitle = title.length > 0 ? 1 : 0;
    features.DomainTitleMatchScore = title.toLowerCase().includes(hostname.toLowerCase()) ? 100 : 0;
    features.URLTitleMatchScore = title.toLowerCase().includes(tlds[0].toLowerCase()) ? 100 : 0;

    features.HasFavicon = $('link[rel="icon"], link[rel="shortcut icon"]').length > 0 ? 1 : 0;
    features.Robots = $('meta[name="robots"]').length > 0 ? 1 : 0;
    features.IsResponsive = $('meta[name="viewport"]').length > 0 ? 1 : 0;
    features.HasDescription = $('meta[name="description"]').length > 0 ? 1 : 0;

    features.NoOfPopup = html.toLowerCase().includes('window.open') ? 1 : 0;
    features.NoOfiFrame = $('iframe').length;
    features.HasExternalFormSubmit = $('form[action^="http"]').filter((_, el) => !$(el).attr('action')?.includes(hostname)).length > 0 ? 1 : 0;

    const socialLinks = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com'];
    features.HasSocialNet = $('a').toArray().some(a => socialLinks.some(sl => $(a).attr('href')?.includes(sl))) ? 1 : 0;

    features.HasSubmitButton = $('button[type="submit"], input[type="submit"]').length > 0 ? 1 : 0;
    features.HasHiddenFields = $('input[type="hidden"]').length > 0 ? 1 : 0;
    features.HasPasswordField = $('input[type="password"]').length > 0 ? 1 : 0;

    const text = $('body').text().toLowerCase();
    features.Bank = text.includes('bank') ? 1 : 0;
    features.Pay = text.includes('pay') ? 1 : 0;
    features.Crypto = text.includes('crypto') || text.includes('bitcoin') || text.includes('wallet') ? 1 : 0;
    features.HasCopyrightInfo = text.includes('copyright') || text.includes('©') ? 1 : 0;

    // Resource Counts
    features.NoOfImage = $('img').length;
    features.NoOfCSS = $('link[rel="stylesheet"]').length;
    features.NoOfJS = $('script').length;

    const links = $('a');
    let selfRef = 0, emptyRef = 0, extRef = 0;
    links.each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href === '#' || href === 'javascript:void(0)') emptyRef++;
      else if (href.startsWith('/') || href.includes(hostname)) selfRef++;
      else if (href.startsWith('http')) extRef++;
    });
    features.NoOfSelfRef = selfRef;
    features.NoOfEmptyRef = emptyRef;
    features.NoOfExternalRef = extRef;

  } catch (error: any) {
    const msg = error?.code || error?.message || 'Unknown error';
    console.log(`[Scraper] Could not reach ${cleanUrl} (${msg}). Web features defaulted to 0.`);
    // If we fail to scrape (e.g., site is down or blocks us), we default the web features to 0
    const webFeatures = [
      'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore',
      'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription',
      'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
      'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo',
      'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
    ];
    webFeatures.forEach(f => features[f] = 0);
  }

  // Advanced Phishing Analysis
  try {
    const { analyzePhishingIndicators, calculateDomainReputation, checkSecurityHeaders } = await import('./advancedPhishingDetection');
    
    const phishingAnalysis = await analyzePhishingIndicators(cleanUrl, features, html);
    features.PhishingScore = phishingAnalysis.phishingScore;
    features.PhishingIndicatorCount = phishingAnalysis.indicators.length;
    features.HasBrandImpersonation = phishingAnalysis.brandImpersonation ? 1 : 0;
    features.HasTyposquatting = phishingAnalysis.typosquatting ? 1 : 0;
    features.HasHomoglyphAttack = phishingAnalysis.homoglyphAttack ? 1 : 0;
    features.HasUrgencyLanguage = phishingAnalysis.urgencyLanguage ? 1 : 0;
    
    const reputation = calculateDomainReputation(hostname, features);
    features.DomainReputation = reputation;
    
    const securityHeaders = await checkSecurityHeaders(cleanUrl);
    features.SecurityHeaderScore = 1.0 - securityHeaders.score;
    features.SecurityHeaderIssues = securityHeaders.issues.length;
  } catch (error) {
    console.log('[Advanced Analysis] Failed, using defaults');
    features.PhishingScore = 0;
    features.PhishingIndicatorCount = 0;
    features.HasBrandImpersonation = 0;
    features.HasTyposquatting = 0;
    features.HasHomoglyphAttack = 0;
    features.HasUrgencyLanguage = 0;
    features.DomainReputation = 0.5;
    features.SecurityHeaderScore = 0.5;
    features.SecurityHeaderIssues = 0;
  }

  return features;
};

