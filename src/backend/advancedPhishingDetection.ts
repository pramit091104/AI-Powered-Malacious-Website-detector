import axios from 'axios';
import * as cheerio from 'cheerio';

/**
 * Advanced Phishing Detection Module
 * Implements cybersecurity expert-level heuristics for phishing detection
 */

// Known legitimate TLDs vs suspicious ones
const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', // Free TLDs commonly abused
    'xyz', 'top', 'work', 'click', 'link', 'online', 'site',
    'pw', 'cc', 'ws', 'info', 'biz'
]);

const LEGITIMATE_TLDS = new Set([
    'com', 'org', 'net', 'edu', 'gov', 'mil',
    'co.uk', 'ac.uk', 'gov.uk'
]);

// Brand impersonation keywords
const BRAND_KEYWORDS = [
    'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'ebay',
    'bank', 'chase', 'wellsfargo', 'citibank', 'bankofamerica',
    'visa', 'mastercard', 'amex', 'discover',
    'dropbox', 'adobe', 'yahoo', 'outlook', 'icloud'
];

// Phishing trigger words
const PHISHING_KEYWORDS = [
    'verify', 'confirm', 'update', 'secure', 'account', 'suspend',
    'locked', 'unusual', 'activity', 'click', 'urgent', 'expire',
    'validate', 'restore', 'limited', 'alert', 'warning'
];

// Legitimate domain patterns
const LEGITIMATE_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'stackoverflow.com', 'wikipedia.org', 'reddit.com'
];

export interface PhishingAnalysis {
    phishingScore: number; // 0-1 scale
    indicators: string[];
    brandImpersonation: boolean;
    suspiciousTLD: boolean;
    typosquatting: boolean;
    homoglyphAttack: boolean;
    urgencyLanguage: boolean;
    certificateIssues: boolean;
}

/**
 * Detect typosquatting - domain similar to legitimate brands
 */
function detectTyposquatting(domain: string): { detected: boolean; target?: string } {
    const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
    
    for (const brand of BRAND_KEYWORDS) {
        // Check if domain contains brand name with modifications
        if (cleanDomain.includes(brand) && !cleanDomain.startsWith(brand + '.')) {
            // Examples: paypa1.com, paypal-secure.com, secure-paypal.com
            if (cleanDomain !== brand + '.com' && cleanDomain !== brand + '.net') {
                return { detected: true, target: brand };
            }
        }
        
        // Levenshtein distance check (simple version)
        const distance = levenshteinDistance(cleanDomain.split('.')[0], brand);
        if (distance > 0 && distance <= 2) {
            return { detected: true, target: brand };
        }
    }
    
    return { detected: false };
}

/**
 * Simple Levenshtein distance for typo detection
 */
function levenshteinDistance(a: string, b: string): number {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    
    const matrix: number[][] = [];
    
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }
    
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    
    return matrix[b.length][a.length];
}

/**
 * Detect homoglyph attacks (lookalike characters)
 */
function detectHomoglyphs(domain: string): boolean {
    // Common homoglyph substitutions
    const homoglyphs = [
        /[а-яА-Я]/, // Cyrillic characters (look like Latin)
        /[α-ωΑ-Ω]/, // Greek characters
        /[０-９]/, // Fullwidth digits
        /[ａ-ｚＡ-Ｚ]/, // Fullwidth Latin
        /[‐‑‒–—―]/, // Various dashes (not standard hyphen)
    ];
    
    return homoglyphs.some(pattern => pattern.test(domain));
}

/**
 * Detect URL obfuscation techniques
 */
function detectObfuscation(url: string): { hasObfuscation: boolean; count: number; ratio: number } {
    let obfuscatedChars = 0;
    
    // URL encoding abuse (%20, %2F, etc.)
    const encodedMatches = url.match(/%[0-9A-Fa-f]{2}/g) || [];
    obfuscatedChars += encodedMatches.length;
    
    // Unicode escapes
    const unicodeMatches = url.match(/\\u[0-9A-Fa-f]{4}/g) || [];
    obfuscatedChars += unicodeMatches.length;
    
    // Hex encoding
    const hexMatches = url.match(/0x[0-9A-Fa-f]+/g) || [];
    obfuscatedChars += hexMatches.length;
    
    // Base64-like patterns
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

/**
 * Analyze TLD legitimacy
 */
function analyzeTLD(hostname: string): { suspicious: boolean; score: number } {
    const parts = hostname.split('.');
    const tld = parts[parts.length - 1].toLowerCase();
    
    if (LEGITIMATE_TLDS.has(tld)) {
        return { suspicious: false, score: 0.9 };
    }
    
    if (SUSPICIOUS_TLDS.has(tld)) {
        return { suspicious: true, score: 0.2 };
    }
    
    // Unknown TLD - moderate suspicion
    return { suspicious: false, score: 0.5 };
}

/**
 * Detect urgency/phishing language patterns
 */
function detectUrgencyLanguage(text: string, title: string): { detected: boolean; matches: string[] } {
    const content = (text + ' ' + title).toLowerCase();
    const matches: string[] = [];
    
    for (const keyword of PHISHING_KEYWORDS) {
        if (content.includes(keyword)) {
            matches.push(keyword);
        }
    }
    
    // Urgency phrases
    const urgencyPhrases = [
        'act now', 'immediate action', 'within 24 hours', 'account will be closed',
        'suspended', 'verify now', 'click here', 'confirm identity',
        'unusual activity', 'security alert', 'action required'
    ];
    
    for (const phrase of urgencyPhrases) {
        if (content.includes(phrase)) {
            matches.push(phrase);
        }
    }
    
    return {
        detected: matches.length > 0,
        matches: matches
    };
}

/**
 * Comprehensive phishing analysis
 */
export async function analyzePhishingIndicators(url: string, features: any, html?: string): Promise<PhishingAnalysis> {
    const indicators: string[] = [];
    let phishingScore = 0;
    
    const urlObj = new URL(url.startsWith('http') ? url : 'http://' + url);
    const hostname = urlObj.hostname;
    
    // 1. TLD Analysis
    const tldAnalysis = analyzeTLD(hostname);
    if (tldAnalysis.suspicious) {
        phishingScore += 0.15;
        indicators.push(`Suspicious TLD: .${hostname.split('.').pop()}`);
    }
    
    // 2. Typosquatting Detection
    const typosquatting = detectTyposquatting(hostname);
    if (typosquatting.detected) {
        phishingScore += 0.25;
        indicators.push(`Typosquatting: Impersonating "${typosquatting.target}"`);
    }
    
    // 3. Homoglyph Attack Detection
    const homoglyphDetected = detectHomoglyphs(hostname);
    if (homoglyphDetected) {
        phishingScore += 0.30;
        indicators.push('Homoglyph attack: Using lookalike characters');
    }
    
    // 4. URL Obfuscation
    const obfuscation = detectObfuscation(url);
    if (obfuscation.hasObfuscation) {
        phishingScore += Math.min(0.20, obfuscation.ratio * 2);
        indicators.push(`URL obfuscation: ${obfuscation.count} encoded characters`);
    }
    
    // 5. IP Address Usage
    if (features.IsDomainIP === 1) {
        phishingScore += 0.20;
        indicators.push('Using IP address instead of domain name');
    }
    
    // 6. No HTTPS
    if (features.IsHTTPS !== 1) {
        phishingScore += 0.15;
        indicators.push('No HTTPS encryption');
        
        // Critical if collecting sensitive data
        if (features.HasPasswordField === 1) {
            phishingScore += 0.25;
            indicators.push('CRITICAL: Password field without HTTPS');
        }
    }
    
    // 7. Suspicious URL Structure
    if (features.URLLength > 75) {
        phishingScore += 0.10;
        indicators.push(`Unusually long URL (${features.URLLength} characters)`);
    }
    
    if (features.NoOfSubDomain > 3) {
        phishingScore += 0.12;
        indicators.push(`Excessive subdomains (${features.NoOfSubDomain})`);
    }
    
    // 8. Content Analysis (if HTML available)
    let urgencyDetected = false;
    if (html) {
        const $ = cheerio.load(html);
        const text = $('body').text();
        const title = $('title').text();
        
        const urgency = detectUrgencyLanguage(text, title);
        if (urgency.detected) {
            urgencyDetected = true;
            phishingScore += Math.min(0.15, urgency.matches.length * 0.03);
            indicators.push(`Urgency language: ${urgency.matches.slice(0, 3).join(', ')}`);
        }
        
        // Brand impersonation in content
        const contentLower = text.toLowerCase();
        for (const brand of BRAND_KEYWORDS) {
            if (contentLower.includes(brand) && !hostname.includes(brand)) {
                phishingScore += 0.15;
                indicators.push(`Brand impersonation: Mentions "${brand}" but domain doesn't match`);
                break;
            }
        }
    }
    
    // 9. External Form Submission
    if (features.HasExternalFormSubmit === 1) {
        phishingScore += 0.18;
        indicators.push('Form submits to external domain');
    }
    
    // 10. Suspicious Form Elements
    if (features.HasHiddenFields === 1) {
        phishingScore += 0.08;
        indicators.push('Hidden form fields detected');
    }
    
    // 11. iFrame Abuse
    if (features.NoOfiFrame > 0) {
        phishingScore += Math.min(0.12, features.NoOfiFrame * 0.04);
        indicators.push(`iFrame injection (${features.NoOfiFrame} frames)`);
    }
    
    // 12. Redirect Chains
    if (features.NoOfURLRedirect > 2) {
        phishingScore += 0.15;
        indicators.push(`Redirect chain (${features.NoOfURLRedirect} redirects)`);
    }
    
    // 13. Missing Trust Indicators
    if (features.HasTitle !== 1) {
        phishingScore += 0.05;
        indicators.push('No page title');
    }
    
    if (features.HasFavicon !== 1) {
        phishingScore += 0.05;
        indicators.push('No favicon');
    }
    
    if (features.DomainTitleMatchScore < 30 && features.HasTitle === 1) {
        phishingScore += 0.10;
        indicators.push('Domain and title mismatch');
    }
    
    // 14. Suspicious Character Patterns
    if (features.SpacialCharRatioInURL > 0.15) {
        phishingScore += 0.10;
        indicators.push(`High special character ratio (${(features.SpacialCharRatioInURL * 100).toFixed(1)}%)`);
    }
    
    if (features.NoOfDegitsInURL > 10) {
        phishingScore += 0.08;
        indicators.push(`Excessive digits (${features.NoOfDegitsInURL})`);
    }
    
    // Clamp score to 0-1
    phishingScore = Math.min(1.0, phishingScore);
    
    return {
        phishingScore,
        indicators,
        brandImpersonation: typosquatting.detected,
        suspiciousTLD: tldAnalysis.suspicious,
        typosquatting: typosquatting.detected,
        homoglyphAttack: homoglyphDetected,
        urgencyLanguage: urgencyDetected,
        certificateIssues: features.IsHTTPS !== 1
    };
}

/**
 * Calculate domain reputation score
 */
export function calculateDomainReputation(hostname: string, features: any): number {
    let reputation = 0.5; // Start neutral
    
    // Check against known legitimate domains
    const cleanDomain = hostname.toLowerCase().replace(/^www\./, '');
    if (LEGITIMATE_DOMAINS.some(d => cleanDomain === d || cleanDomain.endsWith('.' + d))) {
        return 0.95; // High reputation
    }
    
    // Age indicators (older sites are more trustworthy)
    if (features.HasCopyrightInfo === 1) reputation += 0.10;
    if (features.HasSocialNet === 1) reputation += 0.10;
    if (features.LineOfCode > 500) reputation += 0.10;
    
    // Professional indicators
    if (features.IsHTTPS === 1) reputation += 0.15;
    if (features.HasFavicon === 1) reputation += 0.05;
    if (features.IsResponsive === 1) reputation += 0.05;
    if (features.HasDescription === 1) reputation += 0.05;
    
    // Content quality
    if (features.NoOfCSS > 0) reputation += 0.05;
    if (features.NoOfJS > 0) reputation += 0.05;
    if (features.NoOfImage > 5) reputation += 0.05;
    
    // Negative indicators
    if (features.IsDomainIP === 1) reputation -= 0.30;
    if (features.NoOfiFrame > 0) reputation -= 0.10;
    if (features.NoOfPopup > 0) reputation -= 0.10;
    if (features.HasExternalFormSubmit === 1) reputation -= 0.15;
    
    return Math.max(0, Math.min(1, reputation));
}

/**
 * Detect suspicious URL patterns
 */
export function detectSuspiciousPatterns(url: string): { score: number; patterns: string[] } {
    const patterns: string[] = [];
    let score = 0;
    
    const urlLower = url.toLowerCase();
    
    // Multiple hyphens (common in phishing)
    const hyphenCount = (url.match(/-/g) || []).length;
    if (hyphenCount > 3) {
        score += 0.10;
        patterns.push(`Multiple hyphens (${hyphenCount})`);
    }
    
    // @ symbol in URL (credential phishing)
    if (url.includes('@')) {
        score += 0.25;
        patterns.push('@ symbol in URL (credential injection)');
    }
    
    // Double slashes in path
    if (url.split('//').length > 2) {
        score += 0.15;
        patterns.push('Double slashes in path');
    }
    
    // Suspicious keywords in URL
    const suspiciousInUrl = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm'];
    for (const keyword of suspiciousInUrl) {
        if (urlLower.includes(keyword)) {
            score += 0.08;
            patterns.push(`Suspicious keyword: "${keyword}"`);
        }
    }
    
    // Port numbers (often used in phishing)
    if (url.match(/:\d{2,5}\//)) {
        score += 0.12;
        patterns.push('Non-standard port number');
    }
    
    // Data URIs or JavaScript
    if (urlLower.startsWith('data:') || urlLower.startsWith('javascript:')) {
        score += 0.30;
        patterns.push('Data URI or JavaScript protocol');
    }
    
    // Excessive dots
    const dotCount = (url.match(/\./g) || []).length;
    if (dotCount > 5) {
        score += 0.10;
        patterns.push(`Excessive dots (${dotCount})`);
    }
    
    return { score: Math.min(1, score), patterns };
}

/**
 * Check for certificate and security headers
 */
export async function checkSecurityHeaders(url: string): Promise<{ score: number; issues: string[] }> {
    const issues: string[] = [];
    let score = 0;
    
    try {
        const response = await axios.head(url, {
            timeout: 3000,
            validateStatus: () => true,
            maxRedirects: 0
        });
        
        const headers = response.headers;
        
        // Check for security headers
        if (!headers['strict-transport-security']) {
            score += 0.08;
            issues.push('Missing HSTS header');
        }
        
        if (!headers['x-frame-options'] && !headers['content-security-policy']) {
            score += 0.08;
            issues.push('Missing clickjacking protection');
        }
        
        if (!headers['x-content-type-options']) {
            score += 0.05;
            issues.push('Missing MIME-type protection');
        }
        
        // Check for suspicious redirects
        if (response.status >= 300 && response.status < 400) {
            score += 0.10;
            issues.push(`HTTP redirect (${response.status})`);
        }
        
        // Check server header
        const server = headers['server'];
        if (!server || server.toLowerCase().includes('nginx') || server.toLowerCase().includes('apache')) {
            // Normal servers
        } else if (server.toLowerCase().includes('python') || server.toLowerCase().includes('php')) {
            score += 0.05;
            issues.push('Suspicious server configuration');
        }
        
    } catch (error) {
        // Can't reach server or connection issues
        score += 0.15;
        issues.push('Unable to verify security headers');
    }
    
    return { score: Math.min(1, score), issues };
}
