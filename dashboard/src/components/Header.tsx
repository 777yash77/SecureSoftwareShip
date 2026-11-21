import React, { useState, useRef } from 'react';
import {
  Shield,
  Play,
  Download,
  RefreshCw,
  Radio,
  FileCode,
  Award,
  FileSpreadsheet,
  Folder,
  Github,
  UploadCloud,
  FileArchive,
} from 'lucide-react';

interface HeaderProps {
  onRunScan: (path: string, minScore?: number) => Promise<void>;
  onRunGitHubScan: (repoUrl: string) => Promise<void>;
  onUploadZipScan: (file: File) => Promise<void>;
  isLoading: boolean;
  backendOnline: boolean;
  targetPath: string;
  onRefresh: () => void;
}

type ScanMode = 'path' | 'github' | 'upload';

export const Header: React.FC<HeaderProps> = ({
  onRunScan,
  onRunGitHubScan,
  onUploadZipScan,
  isLoading,
  backendOnline,
  targetPath,
  onRefresh,
}) => {
  const [scanMode, setScanMode] = useState<ScanMode>('path');
  const [inputPath, setInputPath] = useState(targetPath || './demo-vulnerable-app');
  const [githubUrl, setGithubUrl] = useState('');
  const [minScore, setMinScore] = useState<number>(80);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  React.useEffect(() => {
    if (targetPath) {
      if (targetPath.includes('github.com')) {
        setScanMode('github');
        setGithubUrl(targetPath.startsWith('http') ? targetPath : `https://${targetPath}`);
      } else {
        setInputPath(targetPath);
      }
    }
  }, [targetPath]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (scanMode === 'path' && inputPath.trim()) {
      onRunScan(inputPath.trim(), minScore);
    } else if (scanMode === 'github' && githubUrl.trim()) {
      onRunGitHubScan(githubUrl.trim());
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (file.name.toLowerCase().endsWith('.zip')) {
        onUploadZipScan(file);
      } else {
        alert('Please select a valid .zip archive.');
      }
    }
  };

  const handleExportHtml = () => {
    window.open('http://127.0.0.1:8787/api/report/html', '_blank');
  };

  const handleExportJson = () => {
    window.open('http://127.0.0.1:8787/api/report/json', '_blank');
  };

  const handleExportSarif = () => {
    window.open('http://127.0.0.1:8787/api/report/sarif', '_blank');
  };

  const handleExportCertificate = () => {
    window.open('http://127.0.0.1:8787/api/report/certificate', '_blank');
  };

  return (
    <header className="border-b border-cyber-border bg-[#090d16]/90 backdrop-blur sticky top-0 z-50 px-6 py-4">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold tracking-tight text-white">SecureShip</span>
              <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">Shift-Left DevSecOps Gate & Security Platform</p>
          </div>
        </div>

        {/* Scan Input & Mode Selector Form */}
        <div className="flex flex-col sm:flex-row items-center gap-2 w-full md:w-auto flex-1 max-w-2xl">
          {/* Mode Switcher Buttons */}
          <div className="flex items-center bg-[#111827] border border-slate-700/80 rounded-lg p-1 text-xs">
            <button
              type="button"
              onClick={() => setScanMode('path')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md font-medium transition-all ${
                scanMode === 'path'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Folder className="w-3.5 h-3.5" />
              <span>Path</span>
            </button>
            <button
              type="button"
              onClick={() => setScanMode('github')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md font-medium transition-all ${
                scanMode === 'github'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Github className="w-3.5 h-3.5" />
              <span>GitHub</span>
            </button>
            <button
              type="button"
              onClick={() => setScanMode('upload')}
              className={`flex items-center gap-1 px-2.5 py-1 rounded-md font-medium transition-all ${
                scanMode === 'upload'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Upload Zip</span>
            </button>
          </div>

          {/* Form depending on Mode */}
          {scanMode === 'upload' ? (
            <div className="flex items-center gap-2 flex-1 w-full">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".zip"
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={isLoading}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 border border-dashed border-cyan-500/50 hover:border-cyan-400 bg-cyan-950/20 hover:bg-cyan-950/40 rounded-lg text-xs md:text-sm text-cyan-300 font-semibold transition-all cursor-pointer"
              >
                <FileArchive className="w-4 h-4 text-cyan-400" />
                <span>{isLoading ? 'Scanning Uploaded Zip...' : 'Choose or Drop Project .zip to Scan'}</span>
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex items-center gap-2 flex-1 w-full">
              <div className="relative flex-1">
                {scanMode === 'github' ? (
                  <input
                    type="text"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    placeholder="GitHub Repo URL (e.g. https://github.com/owner/repo)"
                    className="w-full bg-[#111827] border border-slate-700/80 rounded-lg px-3.5 py-2 text-xs md:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
                  />
                ) : (
                  <input
                    type="text"
                    value={inputPath}
                    onChange={(e) => setInputPath(e.target.value)}
                    placeholder="Local Path (e.g. ./demo-vulnerable-app)"
                    className="w-full bg-[#111827] border border-slate-700/80 rounded-lg px-3.5 py-2 text-xs md:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 font-mono transition-all"
                  />
                )}
              </div>
              <div
                className="flex items-center gap-1 bg-[#111827] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-300"
                title="Custom Ship-Readiness Score Threshold (default 80%)"
              >
                <span className="text-slate-400 font-medium">Gate:</span>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={minScore}
                  onChange={(e) => setMinScore(Math.max(0, Math.min(100, parseInt(e.target.value) || 0)))}
                  className="w-9 bg-transparent text-center text-cyan-300 font-bold focus:outline-none"
                />
                <span className="text-slate-400 font-bold">%</span>
              </div>
              <button
                type="submit"
                disabled={isLoading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 text-xs md:text-sm font-semibold shadow-[0_0_12px_rgba(6,182,212,0.3)] transition-all cursor-pointer whitespace-nowrap"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current" />
                    <span>Run Scan</span>
                  </>
                )}
              </button>
            </form>
          )}
        </div>

        {/* Action Controls & Backend Status */}
        <div className="flex items-center gap-3">
          <div
            className={`flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border ${
              backendOnline
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
            }`}
            title={backendOnline ? 'Engine API online on :8787' : 'Engine API offline'}
          >
            <Radio className={`w-3.5 h-3.5 ${backendOnline ? 'animate-pulse' : ''}`} />
            <span>{backendOnline ? 'API Connected' : 'API Offline'}</span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={handleExportCertificate}
              title="Download Formal Ship Readiness Certificate & Executive Audit Report"
              className="p-2 rounded-lg bg-emerald-950/40 border border-emerald-500/40 hover:border-emerald-400 text-emerald-300 hover:text-white transition-all text-xs font-semibold flex items-center gap-1 shadow-[0_0_10px_rgba(16,185,129,0.15)]"
            >
              <Award className="w-4 h-4 text-emerald-400" />
              <span className="hidden sm:inline">Certificate</span>
            </button>
            <button
              onClick={handleExportSarif}
              title="Export SARIF 2.1.0 (GitHub Code Scanning format)"
              className="p-2 rounded-lg bg-[#111827] border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white transition-all text-xs font-medium flex items-center gap-1"
            >
              <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
              <span className="hidden sm:inline">SARIF</span>
            </button>
            <button
              onClick={handleExportHtml}
              title="Export Standalone HTML Report"
              className="p-2 rounded-lg bg-[#111827] border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white transition-all text-xs font-medium flex items-center gap-1"
            >
              <Download className="w-4 h-4" />
              <span className="hidden sm:inline">HTML</span>
            </button>
            <button
              onClick={handleExportJson}
              title="Export JSON Report"
              className="p-2 rounded-lg bg-[#111827] border border-slate-700 hover:border-slate-500 text-slate-300 hover:text-white transition-all text-xs font-medium flex items-center gap-1"
            >
              <FileCode className="w-4 h-4" />
              <span className="hidden sm:inline">JSON</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
