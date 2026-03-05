import * as tf from '@tensorflow/tfjs';
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

const MODEL_DIR = path.resolve(process.cwd(), 'src/backend/tfjs-model');
const MODEL_FILES = path.resolve(MODEL_DIR, 'model.json');
const SCALER_FILE = path.resolve(process.cwd(), 'src/backend/tf_scaler_params.json');
const CSV_FILE = path.resolve(process.cwd(), 'dataset/urls.csv');

// Memory Cache
let tfModel: tf.LayersModel | null = null;
let scalerParams: { featureNames: string[]; means: number[]; stds: number[] } | null = null;
let preloadedDataset: any[] | null = null;

const ignoredColumns = new Set(['FILENAME', 'URL', 'url', 'Domain', 'domain', 'TLD', 'tld', 'Title', 'title', 'label']);

const getDataset = () => {
    if (!preloadedDataset) {
        if (!fs.existsSync(CSV_FILE)) {
            console.error('CSV dataset not found at ' + CSV_FILE);
            return [];
        }
        console.log('Preloading dataset for TF prediction... This may take a moment.');
        const fileContent = fs.readFileSync(CSV_FILE, 'utf-8').replace(/^\uFEFF/, '');
        preloadedDataset = parse(fileContent, { columns: true, skip_empty_lines: true });
        console.log(`Dataset preloaded successfully. ${preloadedDataset!.length} records.`);
    }
    return preloadedDataset!;
};

const loadTensorFlowEngine = async () => {
    if (!tfModel) {
        if (!fs.existsSync(MODEL_FILES)) {
            throw new Error('TensorFlow model not compiled. Run "npm run train:tf".');
        }
        console.log('Mounting deep learning model into memory...');
        const customLoader: tf.io.IOHandler = {
            load: async () => {
                const modelJson = JSON.parse(fs.readFileSync(MODEL_FILES, 'utf-8'));
                const weightData = fs.readFileSync(path.resolve(MODEL_DIR, 'weights.bin'));
                return {
                    modelTopology: modelJson.modelTopology,
                    weightSpecs: modelJson.weightsManifest[0].weights,
                    weightData: weightData.buffer.slice(weightData.byteOffset, weightData.byteOffset + weightData.byteLength),
                    format: modelJson.format,
                    generatedBy: modelJson.generatedBy,
                    convertedBy: modelJson.convertedBy
                };
            }
        };
        tfModel = await tf.loadLayersModel(customLoader);
        console.log('TensorFlow model loaded successfully.');
    }

    if (!scalerParams) {
        scalerParams = JSON.parse(fs.readFileSync(SCALER_FILE, 'utf-8'));
    }

    return { model: tfModel, scaler: scalerParams! };
};

export const predictUrl = async (url: string): Promise<ScanPrediction> => {
    try {
        const { model, scaler } = await loadTensorFlowEngine();

        console.log(`Deep Learning scan initiated for ${url}...`);

        // Step 1: Check if URL exists in the CSV dataset using fuzzy matching
        const records = getDataset();

        // Build multiple URL format variations the dataset might use
        let cleanInput = url.trim();
        // Strip protocol for comparison
        const stripped = cleanInput.replace(/^https?:\/\//, '').replace(/^www\./, '');
        const variations = [
            cleanInput,
            `http://${stripped}`,
            `https://${stripped}`,
            `http://www.${stripped}`,
            `https://www.${stripped}`,
            stripped,
            `www.${stripped}`,
        ];

        const record = records.find((r: any) => {
            const csvUrl = (r.URL || r.url || '').trim();
            const csvStripped = csvUrl.replace(/^https?:\/\//, '').replace(/^www\./, '');
            return variations.includes(csvUrl) || csvStripped === stripped;
        });

        let features: any = {};
        let source = 'live-scrape';

        if (record) {
            // Found in CSV - use exact dataset features (this is what the model was trained on)
            source = 'dataset';
            for (const key of Object.keys(record)) {
                if (!ignoredColumns.has(key)) {
                    const val = Number(record[key]);
                    features[key] = isNaN(val) ? 0 : val;
                }
            }
            console.log(`Found URL in dataset. Using exact training features.`);
        } else {
            // Not in CSV - dynamically scrape live features
            features = await extractFeaturesAsync(url);
            console.log(`URL not in dataset. Using live-scraped features.`);
        }

        // Prepare array based on EXACT order of columns the network learned
        // For missing/undefined features, use the dataset mean so z-score = 0 (no effect)
        const rawVector = scaler.featureNames.map((key, i) => {
            const val = features[key];
            if (val === undefined || val === null) {
                // Feature not computed by scraper — substitute mean so it has zero influence
                return scaler.means[i];
            }
            const num = Number(val);
            return isNaN(num) ? scaler.means[i] : num;
        });

        // Apply Dataset Scaling (Z-Score)
        const scaledVector = rawVector.map((val, i) => {
            return (val - scaler.means[i]) / scaler.stds[i];
        });

        // Convert standard array into GPU/CPU TensorFlow Tensor object
        const inputTensor = tf.tensor2d([scaledVector]);

        // INFERENCE: Execute the massive mathematical web of neurons instantly
        const predictionTensor = model.predict(inputTensor) as tf.Tensor;
        const probabilityFloatArray = await predictionTensor.data();
        const probability = probabilityFloatArray[0]; // Sigmoid squeezes to 0.0 - 1.0

        console.log(`[DEBUG] Source: ${source}, Features: ${rawVector.length}, Non-zero: ${rawVector.filter(v => v !== 0).length}`);
        console.log(`[DEBUG] TF raw sigmoid probability: ${probability.toFixed(6)}`);

        // Prevent memory leak by destroying temporary tensors
        inputTensor.dispose();
        predictionTensor.dispose();

        // HYBRID PREDICTION SYSTEM
        // Problem: The model was trained on features we can't compute for live URLs
        // Solution: Combine neural network with explicit security checks
        
        let prediction: PredictionResult = 'Safe';
        let confidence = 0;
        let finalScore = probability; // Start with neural network output

        // Import advanced phishing detection
        const { analyzePhishingIndicators } = await import('./advancedPhishingDetection');
        
        // Run advanced phishing analysis
        let phishingAnalysis;
        try {
            phishingAnalysis = await analyzePhishingIndicators(url, features);
        } catch (error) {
            console.log('[Phishing Analysis] Failed, using basic scoring');
            phishingAnalysis = { phishingScore: 0, indicators: [] };
        }

        // Calculate explicit security risk score from available features
        let securityRiskScore = 0;
        let riskFactors: string[] = [];

        // Add phishing-specific score
        if (phishingAnalysis.phishingScore > 0) {
            securityRiskScore += phishingAnalysis.phishingScore * 0.4; // Weight phishing analysis heavily
            riskFactors.push(...phishingAnalysis.indicators);
        }

        // CRITICAL SECURITY CHECKS (High Weight)
        if (features.IsDomainIP === 1) {
            securityRiskScore += 0.25;
            riskFactors.push('IP address domain');
            if (features.IsHTTPS !== 1) {
                securityRiskScore += 0.15;
                riskFactors.push('No HTTPS with IP');
            }
        }

        if (features.IsHTTPS !== 1) {
            securityRiskScore += 0.15;
            riskFactors.push('No HTTPS encryption');
        }

        if (features.HasObfuscation === 1) {
            securityRiskScore += 0.20;
            riskFactors.push('URL obfuscation detected');
            if (features.ObfuscationRatio > 0.3) {
                securityRiskScore += 0.15;
                riskFactors.push('Heavy obfuscation');
            }
        }

        if (features.HasPasswordField === 1 && features.IsHTTPS !== 1) {
            securityRiskScore += 0.30;
            riskFactors.push('Password field without HTTPS');
        }

        if (features.HasExternalFormSubmit === 1) {
            securityRiskScore += 0.15;
            riskFactors.push('External form submission');
            if (features.Bank === 1 || features.Pay === 1 || features.Crypto === 1) {
                securityRiskScore += 0.20;
                riskFactors.push('Financial keywords with external form');
            }
        }

        // Advanced phishing indicators
        if (features.HasTyposquatting === 1) {
            securityRiskScore += 0.30;
            riskFactors.push('Typosquatting detected');
        }

        if (features.HasHomoglyphAttack === 1) {
            securityRiskScore += 0.35;
            riskFactors.push('Homoglyph attack detected');
        }

        if (features.HasBrandImpersonation === 1) {
            securityRiskScore += 0.25;
            riskFactors.push('Brand impersonation');
        }

        if (features.HasUrgencyLanguage === 1) {
            securityRiskScore += 0.15;
            riskFactors.push('Urgency/phishing language');
        }

        // SUSPICIOUS INDICATORS (Medium Weight)
        if (features.URLLength > 75) {
            securityRiskScore += 0.10;
            riskFactors.push(`Long URL (${features.URLLength} chars)`);
        }

        if (features.NoOfSubDomain > 3) {
            securityRiskScore += 0.12;
            riskFactors.push(`Excessive subdomains (${features.NoOfSubDomain})`);
        }

        if (features.SpacialCharRatioInURL > 0.15) {
            securityRiskScore += 0.10;
            riskFactors.push('High special character ratio');
        }

        if (features.NoOfDegitsInURL > 10) {
            securityRiskScore += 0.08;
            riskFactors.push(`Many digits (${features.NoOfDegitsInURL})`);
        }

        if (features.NoOfiFrame > 0) {
            securityRiskScore += 0.10;
            riskFactors.push(`iFrames detected (${features.NoOfiFrame})`);
        }

        if (features.NoOfPopup > 0) {
            securityRiskScore += 0.10;
            riskFactors.push('Popup windows');
        }

        if (features.HasHiddenFields === 1) {
            securityRiskScore += 0.08;
            riskFactors.push('Hidden form fields');
        }

        if (features.NoOfURLRedirect > 2) {
            securityRiskScore += 0.15;
            riskFactors.push(`Multiple redirects (${features.NoOfURLRedirect})`);
        }

        if (features.SuspiciousPatternCount > 2) {
            securityRiskScore += 0.12;
            riskFactors.push(`Suspicious URL patterns (${features.SuspiciousPatternCount})`);
        }

        if (features.SecurityHeaderIssues > 3) {
            securityRiskScore += 0.10;
            riskFactors.push(`Missing security headers (${features.SecurityHeaderIssues})`);
        }

        // TRUST SIGNALS (Reduce Risk)
        let trustScore = 0;
        let trustFactors: string[] = [];

        if (features.IsHTTPS === 1) {
            trustScore += 0.10;
            trustFactors.push('HTTPS enabled');
        }

        if (features.HasTitle === 1 && features.DomainTitleMatchScore > 70) {
            trustScore += 0.08;
            trustFactors.push('Domain matches title');
        }

        if (features.HasFavicon === 1) {
            trustScore += 0.05;
            trustFactors.push('Favicon present');
        }

        if (features.IsResponsive === 1) {
            trustScore += 0.05;
            trustFactors.push('Mobile responsive');
        }

        if (features.HasDescription === 1) {
            trustScore += 0.05;
            trustFactors.push('Meta description');
        }

        if (features.HasSocialNet === 1) {
            trustScore += 0.05;
            trustFactors.push('Social media links');
        }

        if (features.HasCopyrightInfo === 1) {
            trustScore += 0.05;
            trustFactors.push('Copyright info');
        }

        if (features.LineOfCode > 100) {
            trustScore += 0.05;
            trustFactors.push('Substantial content');
        }

        if (features.DomainReputation > 0.7) {
            trustScore += 0.15;
            trustFactors.push(`Good domain reputation (${(features.DomainReputation * 100).toFixed(0)}%)`);
        }

        // COMBINE SCORES
        // If URL is from dataset, trust neural network more (60%)
        // If URL is live-scraped, trust security checks more (70%)
        const nnWeight = source === 'dataset' ? 0.60 : 0.30;
        const securityWeight = 1 - nnWeight;

        finalScore = (probability * nnWeight) + (securityRiskScore * securityWeight) - (trustScore * 0.3);
        finalScore = Math.max(0, Math.min(1, finalScore)); // Clamp to 0-1

        console.log(`[ADVANCED PHISHING DETECTION]`);
        console.log(`  Neural Network: ${(probability * 100).toFixed(1)}% (weight: ${nnWeight})`);
        console.log(`  Security Risk: ${(securityRiskScore * 100).toFixed(1)}% (weight: ${securityWeight})`);
        console.log(`  Phishing Analysis: ${(phishingAnalysis.phishingScore * 100).toFixed(1)}%`);
        console.log(`  Trust Signals: -${(trustScore * 100).toFixed(1)}%`);
        console.log(`  Final Score: ${(finalScore * 100).toFixed(1)}%`);
        if (riskFactors.length > 0) {
            console.log(`  Risk Factors (${riskFactors.length}): ${riskFactors.slice(0, 5).join(', ')}${riskFactors.length > 5 ? '...' : ''}`);
        }
        if (trustFactors.length > 0) {
            console.log(`  Trust Factors (${trustFactors.length}): ${trustFactors.join(', ')}`);
        }

        // CLASSIFICATION with stricter thresholds for phishing
        if (finalScore >= 0.55) {
            prediction = 'Malicious';
            confidence = finalScore;
        } else if (finalScore >= 0.30) {
            prediction = 'Suspicious';
            confidence = Math.max(finalScore, 1.0 - finalScore);
        } else {
            prediction = 'Safe';
            confidence = 1.0 - finalScore;
        }

        console.log(`Final Classification: ${prediction} (confidence=${(confidence * 100).toFixed(1)}%)`);

        return {
            prediction,
            confidence: parseFloat(confidence.toFixed(2)),
            features
        };

    } catch (error: any) {
        console.error('TensorFlow Prediction Error:', error.message);

        // If Model isn't trained yet, provide generic fallback so UI doesn't crash
        const basicFeatures = await extractFeaturesAsync(url);
        let score = 0;
        if (basicFeatures.IsDomainIP === 1) score += 0.5;
        if (basicFeatures.IsHTTPS !== 1) score += 0.3;

        const prob = Math.min(score, 1.0);
        return {
            prediction: prob > 0.7 ? 'Malicious' : prob > 0.3 ? 'Suspicious' : 'Safe',
            confidence: 0.5,
            features: basicFeatures,
        };
    }
};
