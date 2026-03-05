import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';
import { extractFeatures, URLFeatures } from './featureExtraction';

/**
 * A simple Logistic Regression implementation for binary classification.
 * Trains on the dataset and saves weights to a JSON file.
 */

interface TrainingData {
  url: string;
  label: number; // 0 for Safe, 1 for Malicious/Suspicious
}

const WEIGHTS_FILE = path.resolve(process.cwd(), 'src/backend/model_weights.json');

// Sigmoid function
const sigmoid = (z: number): number => 1 / (1 + Math.exp(-z));

async function train() {
  console.log('--- Starting Model Training ---');
  
  const csvPath = path.resolve(process.cwd(), 'dataset/urls.csv');
  if (!fs.existsSync(csvPath)) {
    console.error('Dataset not found at dataset/urls.csv');
    return;
  }

  const fileContent = fs.readFileSync(csvPath, 'utf-8');
  const records: TrainingData[] = parse(fileContent, {
    columns: true,
    skip_empty_lines: true,
  });

  console.log(`Loaded ${records.length} records.`);

  // Prepare features and labels
  const X: number[][] = [];
  const y: number[] = [];
  const featureNames: (keyof URLFeatures)[] = [
    'urlLength', 'dotCount', 'subdomainCount', 'hasIP', 'isHTTPS',
    'suspiciousKeywordCount', 'specialCharCount', 'hyphenCount', 'domainLength', 'redirectCount'
  ];

  for (const record of records) {
    const features = extractFeatures(record.url);
    const featureVector = featureNames.map(name => features[name]);
    // Add bias term (1.0)
    X.push([1.0, ...featureVector]);
    y.push(Number(record.label));
  }

  // Initialize weights (including bias)
  let weights = new Array(featureNames.length + 1).fill(0);
  const learningRate = 0.01;
  const iterations = 5000;

  console.log('Training using Gradient Descent...');

  // Gradient Descent
  for (let i = 0; i < iterations; i++) {
    let gradients = new Array(weights.length).fill(0);
    
    for (let j = 0; j < X.length; j++) {
      const prediction = sigmoid(X[j].reduce((sum, val, idx) => sum + val * weights[idx], 0));
      const error = prediction - y[j];
      
      for (let k = 0; k < weights.length; k++) {
        gradients[k] += error * X[j][k];
      }
    }

    for (let k = 0; k < weights.length; k++) {
      weights[k] -= (learningRate / X.length) * gradients[k];
    }

    if (i % 1000 === 0) {
      console.log(`Iteration ${i}...`);
    }
  }

  // Save weights
  const modelData = {
    featureNames,
    weights,
    trainedAt: new Date().toISOString(),
    accuracy: calculateAccuracy(X, y, weights)
  };

  fs.writeFileSync(WEIGHTS_FILE, JSON.stringify(modelData, null, 2));
  
  console.log('---------------------------------');
  console.log(`Training Complete. Accuracy: ${(modelData.accuracy * 100).toFixed(2)}%`);
  console.log(`Model weights saved to ${WEIGHTS_FILE}`);
}

function calculateAccuracy(X: number[][], y: number[], weights: number[]): number {
  let correct = 0;
  for (let i = 0; i < X.length; i++) {
    const prediction = sigmoid(X[i].reduce((sum, val, idx) => sum + val * weights[idx], 0));
    const label = prediction >= 0.5 ? 1 : 0;
    if (label === y[i]) correct++;
  }
  return correct / y.length;
}

train().catch(console.error);
