import { GoogleGenAI } from "@google/genai";
import { ScanPrediction } from "./predictor";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

export const generateSecurityReport = async (url: string, prediction: ScanPrediction): Promise<string> => {
  const prompt = `
    You are a world-class cybersecurity expert. Generate a security report for the following URL based on a machine learning prediction.

    URL: ${url}
    Prediction: ${prediction.prediction}
    Confidence: ${prediction.confidence * 100}%
    Features Detected:
    - URL Length: ${prediction.features.urlLength}
    - Dot Count: ${prediction.features.dotCount}
    - Subdomain Count: ${prediction.features.subdomainCount}
    - Has IP: ${prediction.features.hasIP === 1 ? 'Yes' : 'No'}
    - Is HTTPS: ${prediction.features.isHTTPS === 1 ? 'Yes' : 'No'}
    - Suspicious Keywords: ${prediction.features.suspiciousKeywordCount}
    - Special Characters: ${prediction.features.specialCharCount}
    - Hyphen Count: ${prediction.features.hyphenCount}
    - Domain Length: ${prediction.features.domainLength}
    - Redirect Count: ${prediction.features.redirectCount}

    The report should include:
    1. Risk Level (Low, Medium, High)
    2. Threat Type (Phishing, Malware Distribution, Credential Harvesting, or Safe)
    3. Indicators Detected (Bullet points)
    4. Explanation in simple language
    5. Recommended Action

    Format the output in a clean, professional structure.
  `;

  try {
    const response = await ai.models.generateContent({
      model: "gemini-1.5-flash",
      contents: prompt,
    });

    return response.text || "Failed to generate report.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Error generating AI security report. Please try again later.";
  }
};
