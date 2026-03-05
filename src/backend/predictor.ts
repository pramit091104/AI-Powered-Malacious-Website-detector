import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';
import { extractFeaturesAsync } from './featureExtraction';

export type PredictionResult = 'Safe' | 'Suspicious' | 'Malicious';

export interface ScanPrediction {
  prediction: PredictionResult;
  confidence: number;
  features: any;
}

interface ModelWeights {
  featureNames: string[];
  weights: number[];
  means?: number[];
  stds?: number[];
  accuracy: number;
}

const WEIGHTS_FILE = path.resolve(process.cwd(), 'src/backend/model_weights.json');
const CSV_FILE = path.resolve(process.cwd(), 'dataset/urls.csv');

// Sigmoid function
const sigmoid = (z: number): number => 1 / (1 + Math.exp(-z));

let preloadedDataset: any[] | null = null;

const getDataset = () => {
  if (!preloadedDataset) {
    if (!fs.existsSync(CSV_FILE)) {
      console.error('CSV dataset not found at ' + CSV_FILE);
      return [];
    }
    console.log('Preloading dataset for prediction... This may take a moment.');
    const fileContent = fs.readFileSync(CSV_FILE, 'utf-8').replace(/^\uFEFF/, '');
    preloadedDataset = parse(fileContent, { columns: true, skip_empty_lines: true });
    console.log('Dataset preloaded successfully.');
  }
  return preloadedDataset;
};

/**
 * Loads the trained model weights and performs prediction.
 */
export const predictUrl = async (url: string): Promise<ScanPrediction> => {
  const records = getDataset();
  const record = records.find((r: any) => r.URL === url || r.url === url);

  const ignoredColumns = new Set(['FILENAME', 'URL', 'url', 'Domain', 'domain', 'TLD', 'tld', 'Title', 'title', 'label']);
  let features: any = {};
  let isNewRecord = false;

  if (record) {
    // Exact match in CSV dataset - load instantly
    for (const key of Object.keys(record)) {
      if (!ignoredColumns.has(key)) {
        const val = Number(record[key]);
        features[key] = isNaN(val) ? 0 : val;
      }
    }
  } else {
    // New URL - perform real-world dynamic scraping
    console.log(`URL not found in dataset. Scraping real-world features for ${url}...`);
    features = await extractFeaturesAsync(url);
    isNewRecord = true;
  }

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

    if (isNewRecord && records.length > 0) {
      try {
        let parsedUrl;
        try {
          parsedUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
        } catch (e) {
          parsedUrl = new URL('http://invalid.internal');
        }

        const newRecord: any = {
          FILENAME: 'live_scraped.txt',
          URL: url,
          Domain: parsedUrl.hostname,
          TLD: parsedUrl.hostname.split('.').pop() || '',
          Title: '',
          label: prediction === 'Safe' ? 0 : 1
        };

        for (const [key, value] of Object.entries(features)) {
          newRecord[key] = value;
        }

        records.push(newRecord);

        const templateRecord = records[0];
        const headers = Object.keys(templateRecord);
        const csvLine = headers.map(h => {
          let val = newRecord[h];
          if (val === undefined) {
            // Handle the invisible BOM in the first column header just in case
            if (h.includes('FILENAME')) val = newRecord['FILENAME'];
            else val = '';
          }
          return typeof val === 'string' && val.includes(',') ? `"${val}"` : val;
        }).join(',') + '\r\n';

        fs.appendFileSync(CSV_FILE, csvLine, 'utf-8');
        console.log(`Successfully appended ${url} and its features to the dataset.`);
      } catch (appendErr) {
        console.error('Failed to append to urls.csv:', appendErr);
      }
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
const fallbackPredict = (url: string, features: any): ScanPrediction => {
  // Basic heuristic
  let score = 0;
  if (features.IsDomainIP === 1 || features.hasIP) score += 0.5;
  if (features.IsHTTPS !== 1 && !features.isHTTPS) score += 0.3;
  if (features.NoOfObfuscatedChar > 0 || features.suspiciousKeywordCount > 0) score += 0.4;

  const prob = Math.min(score, 1.0);
  return {
    prediction: prob > 0.7 ? 'Malicious' : prob > 0.3 ? 'Suspicious' : 'Safe',
    confidence: 0.5, // Low confidence for fallback
    features,
  };
};
