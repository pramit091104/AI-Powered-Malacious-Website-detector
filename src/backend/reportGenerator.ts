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

    if (features.IsHTTPS === 1 || features.isHTTPS === 1) {
        report += `- ✅ Secure Protocol (HTTPS): The connection uses encryption.\n`;
    } else {
        report += `- ❌ Insecure Protocol (HTTP): The connection is NOT encrypted.\n`;
    }

    if (features.IsDomainIP === 1 || features.hasIP === 1) {
        report += `- ⚠️ IP Address Found: The URL domain is an IP address, which is highly used by malware/phishing schemas.\n`;
    } else {
        report += `- ℹ️ Domain Name Used: Normal domain name usage, no bare IP detected.\n`;
    }

    if (features.NoOfURLRedirect > 0 || features.redirectCount > 0) {
        report += `- ⚠️ Potential Redirection: Detected signs of potential URL redirects. This can be used to obfuscate final payloads.\n`;
    }

    if (features.HasObfuscation === 1) {
        report += `- ⚠️ Obfuscation Detected: The URL contains character obfuscation, a common technique to hide malicious intent.\n`;
    }

    if (features.SpacialCharRatioInURL > 0.1) {
        report += `- ⚠️ High Special Character Ratio: The URL has a surprisingly high amount of special characters.\n`;
    }

    report += `\n### Conclusion\n`;
    if (evalResult === 'Malicious') {
        report += `Based on the evaluated indicators from the dataset, this URL exhibits multiple traits strongly correlated with phishing, malware, or spam. Extreme caution is advised. Do not enter credentials on this site.`;
    } else if (evalResult === 'Suspicious') {
        report += `This URL has some concerning traits. Proceed carefully and verify the integrity of the sender.`;
    } else {
        report += `The URL structure does not trigger any major malicious heuristics. However, always exercise baseline caution when browsing unfamiliar sites.`;
    }

    return report;
};
