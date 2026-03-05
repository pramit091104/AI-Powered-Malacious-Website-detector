import { ScanPrediction } from './predictor';

/**
 * Generates a comprehensive text-based security report with detailed threat analysis.
 * Enhanced with advanced phishing detection insights.
 */
export const generateSecurityReport = async (url: string, prediction: ScanPrediction): Promise<string> => {
    const { prediction: evalResult, confidence, features } = prediction;

    let report = `## Advanced Phishing & Security Intelligence Report\n`;
    report += `**URL Analyzed:** \`${url}\`\n`;
    report += `**Threat Level:** ${evalResult.toUpperCase()} (Confidence: ${(confidence * 100).toFixed(1)}%)\n`;
    report += `**Scan Timestamp:** ${new Date().toISOString()}\n\n`;

    // Phishing-Specific Analysis
    if (features.HasTyposquatting === 1 || features.HasHomoglyphAttack === 1 || features.HasBrandImpersonation === 1) {
        report += `### 🎯 PHISHING ATTACK DETECTED\n`;
        if (features.HasTyposquatting === 1) {
            report += `- **Typosquatting**: Domain mimics a legitimate brand with slight variations\n`;
        }
        if (features.HasHomoglyphAttack === 1) {
            report += `- **Homoglyph Attack**: Uses lookalike characters (e.g., Cyrillic 'а' instead of Latin 'a')\n`;
        }
        if (features.HasBrandImpersonation === 1) {
            report += `- **Brand Impersonation**: Attempts to impersonate a well-known company\n`;
        }
        report += `\n`;
    }

    // Critical Security Findings
    const criticalIssues: string[] = [];
    const warnings: string[] = [];
    const positives: string[] = [];

    // Critical Red Flags
    if (features.IsDomainIP === 1 && features.IsHTTPS !== 1) {
        criticalIssues.push('🚨 CRITICAL: IP address used without HTTPS encryption - common phishing tactic');
    }
    if (features.HasObfuscation === 1 && features.ObfuscationRatio > 0.3) {
        criticalIssues.push('🚨 CRITICAL: Heavy URL obfuscation detected - likely malicious intent');
    }
    if (features.NoOfURLRedirect > 2) {
        criticalIssues.push('🚨 CRITICAL: Multiple redirects detected - potential redirect chain attack');
    }
    if (features.HasPasswordField === 1 && features.IsHTTPS !== 1) {
        criticalIssues.push('🚨 CRITICAL: Password field on unencrypted connection - credential theft risk');
    }
    if (features.HasExternalFormSubmit === 1 && (features.Bank === 1 || features.Pay === 1)) {
        criticalIssues.push('🚨 CRITICAL: Financial site with external form submission - phishing indicator');
    }
    if (features.HasHomoglyphAttack === 1) {
        criticalIssues.push('🚨 CRITICAL: Homoglyph attack - sophisticated phishing technique');
    }

    // Warning Signs
    if (features.IsDomainIP === 1 && !criticalIssues.some(i => i.includes('IP address'))) {
        warnings.push('⚠️ Domain uses IP address instead of domain name');
    }
    if (features.IsHTTPS !== 1) {
        warnings.push('⚠️ No HTTPS encryption - data transmitted in plain text');
    }
    if (features.URLLength > 75) {
        warnings.push(`⚠️ Unusually long URL (${features.URLLength} characters) - obfuscation attempt`);
    }
    if (features.NoOfSubDomain > 3) {
        warnings.push(`⚠️ Excessive subdomains (${features.NoOfSubDomain}) - typosquatting indicator`);
    }
    if (features.SpacialCharRatioInURL > 0.15) {
        warnings.push(`⚠️ High special character ratio (${(features.SpacialCharRatioInURL * 100).toFixed(1)}%) - suspicious pattern`);
    }
    if (features.NoOfDegitsInURL > 10) {
        warnings.push(`⚠️ Excessive digits in URL (${features.NoOfDegitsInURL}) - randomization tactic`);
    }
    if (features.NoOfiFrame > 0) {
        warnings.push(`⚠️ Contains ${features.NoOfiFrame} iframe(s) - potential clickjacking risk`);
    }
    if (features.NoOfPopup > 0) {
        warnings.push('⚠️ Popup windows detected - aggressive advertising or malware');
    }
    if (features.HasHiddenFields === 1) {
        warnings.push('⚠️ Hidden form fields present - data collection concern');
    }
    if (features.HasExternalFormSubmit === 1 && !criticalIssues.some(i => i.includes('external form'))) {
        warnings.push('⚠️ Form submits to external domain - data leakage risk');
    }
    if (features.HasTitle !== 1) {
        warnings.push('⚠️ Missing page title - poor legitimacy indicator');
    }
    if (features.HasFavicon !== 1) {
        warnings.push('⚠️ No favicon - unprofessional or hastily created site');
    }
    if (features.DomainTitleMatchScore < 50 && features.HasTitle === 1) {
        warnings.push('⚠️ Domain name doesn\'t match page title - potential impersonation');
    }
    if ((features.Bank === 1 || features.Pay === 1 || features.Crypto === 1) && features.IsHTTPS !== 1) {
        warnings.push('⚠️ Financial keywords on unencrypted site - phishing red flag');
    }
    if (features.HasUrgencyLanguage === 1) {
        warnings.push('⚠️ Urgency/pressure language detected - common phishing tactic');
    }
    if (features.SuspiciousPatternCount > 2) {
        warnings.push(`⚠️ Multiple suspicious URL patterns (${features.SuspiciousPatternCount})`);
    }
    if (features.SecurityHeaderIssues > 3) {
        warnings.push(`⚠️ Missing security headers (${features.SecurityHeaderIssues}) - poor security posture`);
    }

    // Positive Trust Signals
    if (features.IsHTTPS === 1) {
        positives.push('✅ HTTPS encryption enabled');
    }
    if (features.HasTitle === 1 && features.DomainTitleMatchScore > 70) {
        positives.push('✅ Domain matches page title - good legitimacy signal');
    }
    if (features.HasFavicon === 1) {
        positives.push('✅ Favicon present');
    }
    if (features.IsResponsive === 1) {
        positives.push('✅ Mobile-responsive design');
    }
    if (features.HasDescription === 1) {
        positives.push('✅ Meta description present');
    }
    if (features.Robots === 1) {
        positives.push('✅ Robots meta tag configured');
    }
    if (features.HasSocialNet === 1) {
        positives.push('✅ Social media links present');
    }
    if (features.HasCopyrightInfo === 1) {
        positives.push('✅ Copyright information found');
    }
    if (features.LineOfCode > 100) {
        positives.push(`✅ Substantial content (${features.LineOfCode} lines of code)`);
    }
    if (features.DomainReputation > 0.7) {
        positives.push(`✅ Good domain reputation score (${(features.DomainReputation * 100).toFixed(0)}%)`);
    }
    if (features.SecurityHeaderScore > 0.7) {
        positives.push('✅ Proper security headers configured');
    }

    // Build Report Sections
    if (criticalIssues.length > 0) {
        report += `### 🚨 Critical Security Issues\n`;
        criticalIssues.forEach(issue => report += `${issue}\n`);
        report += `\n`;
    }

    if (warnings.length > 0) {
        report += `### ⚠️ Security Warnings (${warnings.length})\n`;
        warnings.forEach(warning => report += `${warning}\n`);
        report += `\n`;
    }

    if (positives.length > 0) {
        report += `### ✅ Positive Indicators (${positives.length})\n`;
        positives.forEach(positive => report += `${positive}\n`);
        report += `\n`;
    }

    // Technical Metrics
    report += `### 📊 Technical Analysis\n`;
    report += `- URL Length: ${features.URLLength} characters\n`;
    report += `- Domain Length: ${features.DomainLength} characters\n`;
    report += `- Subdomains: ${features.NoOfSubDomain}\n`;
    report += `- Special Character Ratio: ${(features.SpacialCharRatioInURL * 100).toFixed(1)}%\n`;
    report += `- Digit Count: ${features.NoOfDegitsInURL}\n`;
    if (features.PhishingScore !== undefined) {
        report += `- Phishing Heuristic Score: ${(features.PhishingScore * 100).toFixed(1)}%\n`;
    }
    if (features.DomainReputation !== undefined) {
        report += `- Domain Reputation: ${(features.DomainReputation * 100).toFixed(0)}%\n`;
    }
    if (features.NoOfImage !== undefined) report += `- Images: ${features.NoOfImage}\n`;
    if (features.NoOfJS !== undefined) report += `- JavaScript Files: ${features.NoOfJS}\n`;
    if (features.NoOfCSS !== undefined) report += `- CSS Files: ${features.NoOfCSS}\n`;
    report += `\n`;

    // Risk Assessment & Recommendations
    report += `### 🎯 Risk Assessment & Recommendations\n`;
    if (evalResult === 'Malicious') {
        report += `**⛔ DANGER - DO NOT PROCEED**\n\n`;
        report += `This URL exhibits multiple characteristics strongly associated with phishing, malware distribution, or credential theft operations. Our advanced detection system, combining neural network analysis with cybersecurity heuristics, has identified this as a HIGH-RISK THREAT.\n\n`;
        report += `**Immediate Actions Required:**\n`;
        report += `1. ❌ Do NOT enter any personal information, passwords, or payment details\n`;
        report += `2. ❌ Do NOT download any files from this site\n`;
        report += `3. ❌ Close the browser tab immediately\n`;
        report += `4. 📢 Report this URL to your IT security team or relevant authorities\n`;
        report += `5. 🛡️ Run a malware scan if you've already interacted with this site\n`;
        report += `6. 🔐 Change passwords if you entered credentials\n`;
    } else if (evalResult === 'Suspicious') {
        report += `**⚠️ CAUTION ADVISED - VERIFY BEFORE PROCEEDING**\n\n`;
        report += `This URL shows concerning patterns that warrant careful scrutiny. While not definitively malicious, it exhibits traits commonly found in phishing attempts, typosquatting, or low-quality websites.\n\n`;
        report += `**Recommended Actions:**\n`;
        report += `1. 🔍 Verify the URL sender through an independent, trusted channel\n`;
        report += `2. 🔤 Check carefully for typos in the domain name (typosquatting)\n`;
        report += `3. 🔒 Do NOT enter sensitive information unless you can verify legitimacy\n`;
        report += `4. 🏆 Look for trust indicators (valid SSL certificate, contact information, reviews)\n`;
        report += `5. 🌐 When in doubt, navigate to the official site directly instead of clicking links\n`;
        report += `6. 📧 If received via email, verify sender authenticity\n`;
    } else {
        report += `**✅ LOW RISK - PROCEED WITH STANDARD CAUTION**\n\n`;
        report += `This URL does not trigger major malicious heuristics based on our comprehensive analysis. The site appears to follow standard web practices and shows positive trust signals.\n\n`;
        report += `**General Security Best Practices:**\n`;
        report += `1. 🔒 Always verify HTTPS encryption before entering sensitive data\n`;
        report += `2. 🚫 Be cautious of unsolicited links, even if they appear safe\n`;
        report += `3. 🔄 Keep your browser and security software up to date\n`;
        report += `4. 🔑 Use unique, strong passwords for each website\n`;
        report += `5. 🛡️ Enable two-factor authentication where available\n`;
    }

    report += `\n---\n`;
    report += `*This report was generated by an AI-powered security analysis system combining:*\n`;
    report += `*- Deep learning neural networks (trained on 235,000+ URLs)*\n`;
    report += `*- Advanced phishing detection (typosquatting, homoglyphs, brand impersonation)*\n`;
    report += `*- Cybersecurity heuristics (OWASP, NIST guidelines)*\n`;
    report += `*- Real-time web scraping and analysis*\n\n`;
    report += `*While highly accurate, no automated system is perfect. Always exercise caution online.*`;

    return report;
};
