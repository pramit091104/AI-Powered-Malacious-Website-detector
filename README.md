# AI-Powered Malicious Website Detection System

This system uses a combination of **Machine Learning (Feature Extraction & Scoring)** and **LLM (Gemini 1.5 Pro)** to detect and analyze malicious URLs.

## Features
- **URL Feature Extraction**: Analyzes 10+ cybersecurity indicators (URL length, dot count, subdomain count, IP usage, HTTPS, suspicious keywords, etc.).
- **ML Scoring Engine**: A weighted scoring model (mimicking XGBoost) that predicts if a URL is Safe, Suspicious, or Malicious.
- **AI Security Report**: Uses Gemini 1.5 Pro to generate a deep-dive security analysis, threat classification, and recommended actions.
- **Scan History**: Stores all previous scans in a local SQLite database for future reference.
- **Cyber-Security Dashboard**: A modern, high-contrast UI built with React and Tailwind CSS.

## Technology Stack
- **Backend**: Node.js (Express)
- **Frontend**: React (Vite)
- **Database**: SQLite (better-sqlite3)
- **LLM**: Gemini 1.5 Pro (@google/genai)
- **Styling**: Tailwind CSS
- **Animations**: Framer Motion

## Training with your own dataset

1.  **Prepare your dataset**:
    -   Create or update `dataset/urls.csv`.
    -   The CSV must have two columns: `url` and `label`.
    -   `label` should be `0` for Safe and `1` for Malicious/Suspicious.
2.  **Run the training script**:
    ```bash
    npm run train
    ```
    This script will:
    -   Read your CSV.
    -   Extract features for each URL.
    -   Train a **Logistic Regression** model using Gradient Descent.
    -   Save the trained weights to `src/backend/model_weights.json`.
3.  **The system will automatically load the new weights**:
    -   The `predictor.ts` loads `model_weights.json` on every scan.
    -   No hardcoded scoring is used once the model is trained.

## Project Structure
- `server.ts`: Main entry point (Express + Vite middleware).
- `src/backend/`:
  - `featureExtraction.ts`: URL analysis logic.
  - `predictor.ts`: ML prediction engine.
  - `database.ts`: SQLite persistence layer.
  - `gemini.ts`: AI report generation.
  - `train.ts`: Model calibration script.
- `src/App.tsx`: Main React frontend.

## Example Test URLs
- **Safe**: `https://www.google.com`, `https://github.com`
- **Suspicious**: `http://192.168.1.1/admin`, `https://amazon-security-check.co`
- **Malicious**: `http://secure-login-paypal-verify.com`, `https://wellsfargo-update-account.net`
