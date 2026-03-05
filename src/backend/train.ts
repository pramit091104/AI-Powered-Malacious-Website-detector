import { predictUrl } from './predictor';

/**
 * A simulated training script that evaluates the model against a small test dataset.
 * In a real scenario, this would use a large CSV and XGBoost/Scikit-learn.
 */
const testDataset = [
  { url: 'https://www.google.com', label: 'Safe' },
  { url: 'https://www.github.com', label: 'Safe' },
  { url: 'http://secure-login-paypal-verify.com', label: 'Malicious' },
  { url: 'http://192.168.1.1/admin', label: 'Suspicious' },
  { url: 'https://wellsfargo-update-account.net', label: 'Malicious' },
  { url: 'https://amazon-security-check.co', label: 'Suspicious' },
  { url: 'https://microsoft.com', label: 'Safe' },
];

async function train() {
  console.log('--- Starting Model Calibration ---');
  console.log('Loading dataset...');
  
  let correct = 0;
  
  for (const item of testDataset) {
    const result = predictUrl(item.url);
    const isCorrect = result.prediction === item.label;
    if (isCorrect) correct++;
    
    console.log(`URL: ${item.url.padEnd(40)} | Expected: ${item.label.padEnd(10)} | Predicted: ${result.prediction.padEnd(10)} | ${isCorrect ? '✅' : '❌'}`);
  }
  
  const accuracy = (correct / testDataset.length) * 100;
  console.log('---------------------------------');
  console.log(`Calibration Complete. Accuracy: ${accuracy.toFixed(2)}%`);
  console.log('Model weights saved to memory.');
}

train();
