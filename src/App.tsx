import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldCheck, History, Search, Loader2, AlertTriangle, ExternalLink, ChevronRight, Info, Download } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { jsPDF } from 'jspdf';

interface ScanResult {
  id?: number;
  url: string;
  prediction: string;
  confidence: number;
  report: string;
  timestamp?: string;
  features?: any;
}

export default function App() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'history'>('scan');

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch('/api/scan-history');
      if (response.ok) {
        const data = await response.json();
        setHistory(data);
      }
    } catch (err) {
      console.error('Failed to fetch history:', err);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/scan-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error('Scan failed. Please check the URL and try again.');
      }

      const data = await response.json();
      setResult(data);
      fetchHistory();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const downloadPDF = (reportText: string, currentUrl: string) => {
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text('Security Intelligence Report', 20, 20);

    doc.setFontSize(10);
    doc.text(`Scanned URL: ${currentUrl}`, 20, 30);
    doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 35);

    // Split text to fit PDF width
    const splitText = doc.splitTextToSize(reportText, 170);
    doc.text(splitText, 20, 45);

    doc.save(`security-report-${currentUrl.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`);
  };

  const getStatusColor = (prediction: string) => {
    switch (prediction.toLowerCase()) {
      case 'safe': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20';
      case 'suspicious': return 'text-amber-400 bg-amber-400/10 border-amber-400/20';
      case 'malicious': return 'text-rose-400 bg-rose-400/10 border-rose-400/20';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/20';
    }
  };

  const getStatusIcon = (prediction: string) => {
    switch (prediction.toLowerCase()) {
      case 'safe': return <ShieldCheck className="w-6 h-6" />;
      case 'suspicious': return <AlertTriangle className="w-6 h-6" />;
      case 'malicious': return <ShieldAlert className="w-6 h-6" />;
      default: return <Shield className="w-6 h-6" />;
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-slate-200 font-sans selection:bg-emerald-500/30">
      {/* Header */}
      <header className="border-b border-white/5 bg-black/40 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Shield className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-white">AI Malicious URL Detector</h1>
              <p className="text-[10px] uppercase tracking-widest text-slate-500 font-mono">Cyber-Security Intelligence</p>
            </div>
          </div>
          <nav className="flex gap-1 p-1 bg-white/5 rounded-lg">
            <button
              onClick={() => setActiveTab('scan')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${activeTab === 'scan' ? 'bg-white/10 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Scanner
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all ${activeTab === 'history' ? 'bg-white/10 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
            >
              History
            </button>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-12">
        <AnimatePresence mode="wait">
          {activeTab === 'scan' ? (
            <motion.div
              key="scan"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-8"
            >
              {/* Hero Section */}
              <div className="max-w-2xl mx-auto text-center space-y-4">
                <h2 className="text-4xl font-bold text-white tracking-tight">Scan any URL for threats</h2>
                <p className="text-slate-400 text-lg">Our AI-powered engine analyzes URL features and generates a comprehensive security report in seconds.</p>
              </div>

              {/* Search Bar */}
              <div className="max-w-3xl mx-auto">
                <form onSubmit={handleScan} className="relative group">
                  <div className="absolute inset-0 bg-emerald-500/20 blur-2xl opacity-0 group-focus-within:opacity-100 transition-opacity duration-500" />
                  <div className="relative flex items-center bg-white/5 border border-white/10 rounded-2xl p-2 focus-within:border-emerald-500/50 focus-within:ring-4 focus-within:ring-emerald-500/10 transition-all duration-300">
                    <Search className="w-6 h-6 text-slate-500 ml-4" />
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="Enter URL to scan (e.g., secure-login-paypal.com)"
                      className="flex-1 bg-transparent border-none focus:ring-0 text-lg px-4 py-3 text-white placeholder:text-slate-600"
                    />
                    <button
                      type="submit"
                      disabled={isScanning || !url}
                      className="bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-800 disabled:text-slate-500 text-black font-bold px-8 py-3 rounded-xl transition-all flex items-center gap-2"
                    >
                      {isScanning ? (
                        <>
                          <Loader2 className="w-5 h-5 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        'Scan Website'
                      )}
                    </button>
                  </div>
                </form>
                {error && (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="mt-4 text-rose-400 text-sm text-center flex items-center justify-center gap-2"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    {error}
                  </motion.p>
                )}
              </div>

              {/* Results */}
              <AnimatePresence>
                {result && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6"
                  >
                    {/* Prediction Card */}
                    <div className="md:col-span-1 space-y-6">
                      <div className={`p-8 rounded-3xl border ${getStatusColor(result.prediction)} flex flex-col items-center text-center space-y-4`}>
                        <div className="p-4 rounded-2xl bg-white/10">
                          {getStatusIcon(result.prediction)}
                        </div>
                        <div>
                          <p className="text-xs uppercase tracking-widest font-mono opacity-60 mb-1">Prediction</p>
                          <h3 className="text-3xl font-bold">{result.prediction}</h3>
                        </div>
                        <div className="w-full bg-white/10 rounded-full h-2 overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${result.confidence * 100}%` }}
                            className={`h-full ${result.prediction === 'Safe' ? 'bg-emerald-400' : result.prediction === 'Suspicious' ? 'bg-amber-400' : 'bg-rose-400'}`}
                          />
                        </div>
                        <p className="text-sm font-mono opacity-80">Confidence: {(result.confidence * 100).toFixed(1)}%</p>
                      </div>

                      {/* Features List */}
                      {result.features && (
                        <div className="p-6 rounded-3xl bg-white/5 border border-white/10 space-y-4">
                          <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                            <Info className="w-4 h-4 text-emerald-400" />
                            Extracted Features
                          </h4>
                          <div className="space-y-2 font-mono text-[11px]">
                            {Object.entries(result.features).map(([key, value]: [string, any]) => (
                              <div key={key} className="flex justify-between py-1 border-b border-white/5 last:border-0 text-slate-400">
                                <span className="capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                                <span className="text-white">{typeof value === 'number' ? value : value.toString()}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* AI Report Card */}
                    <div className="md:col-span-2 p-8 rounded-3xl bg-white/5 border border-white/10 space-y-6">
                      <div className="flex items-center justify-between">
                        <h3 className="text-xl font-bold text-white flex items-center gap-2">
                          <ShieldCheck className="w-6 h-6 text-emerald-400" />
                          AI Security Intelligence Report
                        </h3>
                        <span className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded border border-emerald-500/20">
                          Heuristic Analysis
                        </span>
                        <button
                          onClick={() => downloadPDF(result.report, result.url)}
                          className="text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 bg-white/10 hover:bg-white/20 text-white px-3 py-1.5 rounded-lg border border-white/10 transition-colors"
                        >
                          <Download className="w-3 h-3" />
                          Download PDF
                        </button>
                      </div>
                      <div className="prose prose-invert max-w-none">
                        <div className="whitespace-pre-wrap text-slate-300 leading-relaxed font-mono text-sm bg-black/40 p-6 rounded-2xl border border-white/5">
                          {result.report}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ) : (
            <motion.div
              key="history"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="max-w-5xl mx-auto space-y-6"
            >
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h2 className="text-3xl font-bold text-white tracking-tight">Scan History</h2>
                  <p className="text-slate-400">Review previous intelligence reports and detected threats.</p>
                </div>
                <div className="p-3 rounded-2xl bg-white/5 border border-white/10">
                  <History className="w-6 h-6 text-emerald-400" />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                {history.length === 0 ? (
                  <div className="text-center py-20 bg-white/5 rounded-3xl border border-dashed border-white/10">
                    <p className="text-slate-500">No scan history found. Start by scanning a URL.</p>
                  </div>
                ) : (
                  history.map((item) => (
                    <motion.div
                      key={item.id}
                      layoutId={`item-${item.id}`}
                      onClick={() => {
                        setResult(item);
                        setActiveTab('scan');
                      }}
                      className="group p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 hover:bg-white/[0.07] transition-all cursor-pointer flex items-center justify-between"
                    >
                      <div className="flex items-center gap-6">
                        <div className={`p-3 rounded-xl ${getStatusColor(item.prediction)}`}>
                          {getStatusIcon(item.prediction)}
                        </div>
                        <div>
                          <h4 className="text-white font-medium truncate max-w-md">{item.url}</h4>
                          <div className="flex items-center gap-3 mt-1">
                            <span className={`text-[10px] font-bold uppercase tracking-wider ${getStatusColor(item.prediction).split(' ')[0]}`}>
                              {item.prediction}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">
                              {new Date(item.timestamp!).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right hidden sm:block">
                          <p className="text-[10px] uppercase tracking-widest text-slate-500 font-mono">Confidence</p>
                          <p className="text-sm font-bold text-white">{(item.confidence * 100).toFixed(1)}%</p>
                        </div>
                        <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-white transition-colors" />
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 py-12 mt-20">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-2 text-slate-500 text-sm">
            <Shield className="w-4 h-4" />
            <span>AI Malicious URL Detector © 2024</span>
          </div>
          <div className="flex gap-8 text-sm text-slate-500">
            <a href="#" className="hover:text-emerald-400 transition-colors">Documentation</a>
            <a href="#" className="hover:text-emerald-400 transition-colors">API Reference</a>
            <a href="#" className="hover:text-emerald-400 transition-colors">Privacy Policy</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
