import * as tf from '@tensorflow/tfjs';
import fs from 'fs';
import path from 'path';
import { parse } from 'csv-parse/sync';

interface TrainingData {
    [key: string]: string | number;
}

const train = async () => {
    const csvPath = path.resolve(process.cwd(), 'dataset/urls.csv');
    const weightsDir = path.resolve(process.cwd(), 'src/backend/tfjs-model');

    console.log('\n--- Starting TensorFlow Model Training ---');

    if (!fs.existsSync(csvPath)) {
        console.error(`Dataset not found at ${csvPath}`);
        return;
    }

    // Ensure output directory exists
    if (!fs.existsSync(weightsDir)) {
        fs.mkdirSync(weightsDir, { recursive: true });
    }

    const fileContent = fs.readFileSync(csvPath, 'utf-8').replace(/^\uFEFF/, '');
    const records: TrainingData[] = parse(fileContent, {
        columns: true,
        skip_empty_lines: true,
    });

    console.log(`Loaded ${records.length} records.`);

    const ignoredColumns = new Set(['FILENAME', 'URL', 'url', 'Domain', 'domain', 'TLD', 'tld', 'Title', 'title', 'label']);
    const featureNames = Object.keys(records[0]).filter(col => {
        const cleanCol = col.replace(/^\uFEFF/, '').trim();
        const sanitizedCol = cleanCol.replace(/[^a-zA-Z0-9_]/g, '');
        return !ignoredColumns.has(sanitizedCol) && !ignoredColumns.has(cleanCol) && !ignoredColumns.has(col);
    });

    console.log(`Using ${featureNames.length} features for training.`);

    // Prepare standard arrays
    const X_arr: number[][] = [];
    const y_arr: number[] = [];

    for (const record of records) {
        const url = record.URL || record.url;
        if (!url) continue;

        const featureVector = featureNames.map(name => {
            const val = Number(record[name]);
            return isNaN(val) ? 0 : val;
        });

        X_arr.push(featureVector);
        y_arr.push(Number(record.label));
    }

    console.log('Calculating feature normalization params...');

    // Calculate Means and Stds manually for scaling (so Predictor can use them)
    const means = new Array(featureNames.length).fill(0);
    const stds = new Array(featureNames.length).fill(0);
    const n = X_arr.length;

    for (let i = 0; i < n; i++) {
        for (let j = 0; j < featureNames.length; j++) {
            means[j] += X_arr[i][j];
        }
    }
    for (let j = 0; j < featureNames.length; j++) {
        means[j] /= n;
    }

    for (let i = 0; i < n; i++) {
        for (let j = 0; j < featureNames.length; j++) {
            stds[j] += Math.pow(X_arr[i][j] - means[j], 2);
        }
    }
    for (let j = 0; j < featureNames.length; j++) {
        stds[j] = Math.sqrt(stds[j] / (n > 1 ? n - 1 : 1));
        if (stds[j] === 0) stds[j] = 1; // Prevent division by zero
    }

    // Normalize data array
    console.log('Normalizing dataset features...');
    for (let i = 0; i < n; i++) {
        for (let j = 0; j < featureNames.length; j++) {
            X_arr[i][j] = (X_arr[i][j] - means[j]) / stds[j];
        }
    }

    // Save Scaler parameters for inference
    const scalerParamsPath = path.resolve(process.cwd(), 'src/backend/tf_scaler_params.json');
    fs.writeFileSync(scalerParamsPath, JSON.stringify({
        featureNames,
        means,
        stds
    }, null, 2));

    console.log('Converting to WebGL Tensors...');

    // Convert standard arrays into massive GPU/CPU-optimized Tensors
    const xTensor = tf.tensor2d(X_arr);
    const yTensor = tf.tensor2d(y_arr, [y_arr.length, 1]);

    console.log('Building Neural Network Architecture...');

    // Build the TensorFlow Sequential AI Model
    const model = tf.sequential();

    // Hidden Layer 1: 64 neurons (ReLU activation introduces non-linearity)
    model.add(tf.layers.dense({
        inputShape: [featureNames.length],
        units: 64,
        activation: 'relu'
    }));

    // Hidden Layer 2: 32 neurons
    model.add(tf.layers.dense({
        units: 32,
        activation: 'relu'
    }));

    // Output Layer: 1 neuron (Sigmoid squeezes prediction between 0-1)
    model.add(tf.layers.dense({
        units: 1,
        activation: 'sigmoid'
    }));

    // Compile with Adam Optimizer (adaptive learning rate)
    model.compile({
        optimizer: tf.train.adam(0.005),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
    });

    console.log('Training Neural Network (this will take a moment)...');

    // Train the model
    await model.fit(xTensor, yTensor, {
        epochs: 25, // Pass over the 235k rows 25 times
        batchSize: 512, // Feed 512 URLs into the CPU at once
        validationSplit: 0.1, // Set aside 10% of data to verify it's really learning
        callbacks: {
            onEpochEnd: (epoch, logs) => {
                console.log(`Epoch ${epoch + 1}/25 - loss: ${(logs?.loss || 0).toFixed(4)} - acc: ${(logs?.acc || 0).toFixed(4)} - val_loss: ${(logs?.val_loss || 0).toFixed(4)} - val_acc: ${(logs?.val_acc || 0).toFixed(4)}`);
            }
        }
    });

    // Custom file system handler since we aren't using tfjs-node
    await model.save(tf.io.withSaveHandler(async (artifacts: any) => {
        const modelJson = {
            modelTopology: artifacts.modelTopology,
            format: artifacts.format,
            generatedBy: artifacts.generatedBy,
            convertedBy: artifacts.convertedBy,
            weightsManifest: [{
                paths: ['weights.bin'],
                weights: artifacts.weightSpecs
            }]
        };
        fs.writeFileSync(path.join(weightsDir, 'model.json'), JSON.stringify(modelJson));
        if (artifacts.weightData) {
            fs.writeFileSync(path.join(weightsDir, 'weights.bin'), Buffer.from(artifacts.weightData));
        }
        return { modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON' } } as any;
    }));
    console.log(`\nNeural Network saved successfully to ${weightsDir}`);

    // Cleanup Tensors to prevent memory leak
    xTensor.dispose();
    yTensor.dispose();
};

train().catch(console.error);
