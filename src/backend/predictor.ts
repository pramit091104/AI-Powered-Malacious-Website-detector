import { extractFeatures, URLFeatures } from './featureExtraction';

export type PredictionResult = 'Safe' | 'Suspicious' | 'Malicious';

export interface ScanPrediction {
  prediction: PredictionResult;
  confidence: number;
  features: URLFeatures;
}

/**
 * A weighted scoring model that mimics a trained XGBoost classifier.
 * In a production environment, these weights would be derived from a real training pipeline.
 */
export const predictUrl = (url: string): ScanPrediction => {
  const features = extractFeatures(url);
  let score = 0;

  // 1. URL Length (Longer URLs are often more suspicious)
  if (features.urlLength > 100) score += 0.15;
  if (features.urlLength > 200) score += 0.25;

  // 2. Dot Count (More dots often indicate subdomains or obfuscation)
  if (features.dotCount > 3) score += 0.2;
  if (features.dotCount > 5) score += 0.3;

  // 3. Subdomain Count
  if (features.subdomainCount > 1) score += 0.25;
  if (features.subdomainCount > 3) score += 0.4;

  // 4. Presence of IP Address (Direct IP access is highly suspicious)
  if (features.hasIP === 1) score += 0.8;

  // 5. HTTPS Usage (Lack of HTTPS is a red flag)
  if (features.isHTTPS === 0) score += 0.4;

  // 6. Suspicious Keywords
  if (features.suspiciousKeywordCount > 0) score += 0.3 * features.suspiciousKeywordCount;

  // 7. Special Characters
  if (features.specialCharCount > 2) score += 0.2;
  if (features.specialCharCount > 5) score += 0.4;

  // 8. Hyphen Count
  if (features.hyphenCount > 2) score += 0.15;
  if (features.hyphenCount > 5) score += 0.3;

  // 9. Domain Length
  if (features.domainLength > 30) score += 0.1;
  if (features.domainLength > 50) score += 0.25;

  // 10. Redirect Count
  if (features.redirectCount > 0) score += 0.5;

  // Normalize score to 0-1 range
  const normalizedScore = Math.min(score, 1.0);

  let prediction: PredictionResult = 'Safe';
  let confidence = 0;

  if (normalizedScore > 0.75) {
    prediction = 'Malicious';
    confidence = normalizedScore;
  } else if (normalizedScore > 0.4) {
    prediction = 'Suspicious';
    confidence = normalizedScore;
  } else {
    prediction = 'Safe';
    confidence = 1.0 - normalizedScore;
  }

  return {
    prediction,
    confidence: parseFloat(confidence.toFixed(2)),
    features,
  };
};
