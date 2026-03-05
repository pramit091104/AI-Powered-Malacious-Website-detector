import fs from 'fs';
import path from 'path';
import { extractFeatures, URLFeatures } from './featureExtraction';

export type PredictionResult = 'Safe' | 'Suspicious' | 'Malicious';

export interface ScanPrediction {
  prediction: PredictionResult;
  confidence: number;
  features: URLFeatures;
}

interface ModelWeights {
  featureNames: (keyof URLFeatures)[];
  weights: number[];
  means?: number[];
  stds?: number[];
  accuracy: number;
}

const WEIGHTS_FILE = path.resolve(process.cwd(), 'src/backend/model_weights.json');

// Sigmoid function
const sigmoid = (z: number): number => 1 / (1 + Math.exp(-z));

/**
 * Loads the trained model weights and performs prediction.
 */
export const predictUrl = (url: string): ScanPrediction => {
  const features = extractFeatures(url);

  if (!fs.existsSync(WEIGHTS_FILE)) {
    console.warn('Model weights not found. Please run "npm run train" first.');
    // Fallback to a basic heuristic if not trained yet
    return fallbackPredict(url, features);
  }

  try {
    const modelData: ModelWeights = JSON.parse(fs.readFileSync(WEIGHTS_FILE, 'utf-8'));
    const { featureNames, weights, means, stds } = modelData;

    // Calculate dot product: bias + sum(feature * weight)
    let z = weights[0]; // weights[0] is the bias
    for (let i = 0; i < featureNames.length; i++) {
      let val = Number(features[featureNames[i]]);
      if (means && stds) {
        val = (val - means[i]) / stds[i];
      }
      z += val * weights[i + 1];
    }

    const probability = sigmoid(z);

    let prediction: PredictionResult = 'Safe';
    let confidence = 0;

    if (probability > 0.8) {
      prediction = 'Malicious';
      confidence = probability;
    } else if (probability > 0.4) {
      prediction = 'Suspicious';
      confidence = probability;
    } else {
      prediction = 'Safe';
      confidence = 1.0 - probability;
    }

    return {
      prediction,
      confidence: parseFloat(confidence.toFixed(2)),
      features,
    };
  } catch (error) {
    console.error('Error loading model weights:', error);
    return fallbackPredict(url, features);
  }
};

/**
 * Simple fallback logic if no model is trained.
 */
const fallbackPredict = (url: string, features: URLFeatures): ScanPrediction => {
  // Basic heuristic
  let score = 0;
  if (features.hasIP) score += 0.5;
  if (!features.isHTTPS) score += 0.3;
  if (features.suspiciousKeywordCount > 0) score += 0.4;

  const prob = Math.min(score, 1.0);
  return {
    prediction: prob > 0.7 ? 'Malicious' : prob > 0.3 ? 'Suspicious' : 'Safe',
    confidence: 0.5, // Low confidence for fallback
    features,
  };
};
