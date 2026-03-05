import { ScanPrediction } from './predictor';

/**
 * Generates a text-based security report without calling any external AI API.
 */
export const generateSecurityReport = async (url: string, prediction: ScanPrediction): Promise<string> => {
    const { prediction: evalResult, confidence, features } = prediction;

    let report = `## URL Security Scan Report\n`;
    report += `**URL Analyzed:** \`${url}\`\n`;
    report += `**Threat Level Assessment:** ${evalResult.toUpperCase()} (Confidence: ${(confidence * 100).toFixed(2)}%)\n\n`;

    report += `### Technical Feature Analysis\n`;

    if (features.isHTTPS) {
        report += `- ✅ Secure Protocol (HTTPS): The connection uses encryption.\n`;
    } else {
        report += `- ❌ Insecure Protocol (HTTP): The connection is NOT encrypted.\n`;
    }

    if (features.hasIP) {
        report += `- ⚠️ IP Address Found: The URL domain is an IP address, which is highly used by malware/phishing schemas.\n`;
    } else {
        report += `- ℹ️ Domain Name Used: Normal domain name usage, no bare IP detected.\n`;
    }

    if (features.suspiciousKeywordCount > 0) {
        report += `- ⚠️ Suspicious Keywords: Found ${features.suspiciousKeywordCount} keyword(s) matching known phishing schemes (e.g., 'login', 'secure', 'verify').\n`;
    } else {
        report += `- ℹ️ No Suspicious Keywords: Common phishing keywords were not detected in the URL path.\n`;
    }

    if (features.isShortener) {
        report += `- ⚠️ Shortener Service: This URL is using a known link shortener, which can hide the true destination.\n`;
    }

    if (features.redirectCount > 0) {
        report += `- ⚠️ Potential Redirection: Detected signs of potential URL redirects (${features.redirectCount}). This can be used to obfuscate final payloads.\n`;
    }

    report += `\n### Conclusion\n`;
    if (evalResult === 'Malicious') {
        report += `Based on the evaluated indicators, this URL exhibits multiple traits strongly correlated with phishing, malware, or spam. Extreme caution is advised. Do not enter credentials on this site.`;
    } else if (evalResult === 'Suspicious') {
        report += `This URL has some concerning traits, such as odd keywords, lack of encryption, or unusual length/structure. Proceed carefully and verify the integrity of the sender.`;
    } else {
        report += `The URL structure does not trigger any major malicious heuristics. However, always exercise baseline caution when browsing unfamiliar sites.`;
    }

    return report;
};
