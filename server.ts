import express from 'express';
import { createServer as createViteServer } from 'vite';
import { predictUrl } from './src/backend/predictor_tf';
import { generateSecurityReport } from './src/backend/reportGenerator';
import { saveScan, getScanHistory } from './src/backend/database';
import path from 'path';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Routes
  app.post('/api/scan-url', async (req, res) => {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Invalid URL provided.' });
    }

    try {
      // 1. Predict using ML model (either via fast CSV loopkup or live scraping)
      const prediction = await predictUrl(url);

      // 2. Generate AI Security Report
      const report = await generateSecurityReport(url, prediction);

      // 3. Save to database
      saveScan({
        url,
        prediction: prediction.prediction,
        confidence: prediction.confidence,
        report,
      });

      res.json({
        url,
        prediction: prediction.prediction,
        confidence: prediction.confidence,
        report,
        features: prediction.features,
      });
    } catch (error) {
      console.error('Scan Error:', error);
      res.status(500).json({ error: 'An error occurred during the scan.' });
    }
  });

  app.get('/api/scan-history', (req, res) => {
    try {
      const history = getScanHistory();
      res.json(history);
    } catch (error) {
      console.error('History Fetch Error:', error);
      res.status(500).json({ error: 'Failed to fetch scan history.' });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve static files in production
    app.use(express.static(path.resolve(process.cwd(), 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(process.cwd(), 'dist/index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
