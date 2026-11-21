import React, { useEffect, useState } from 'react';
import { ScanResult, Finding, ShipStatus } from './types';
import { Header } from './components/Header';
import { ShipBanner } from './components/ShipBanner';
import { KpiGrid } from './components/KpiGrid';
import { SeverityCharts } from './components/SeverityCharts';
import { FindingsTable } from './components/FindingsTable';
import { ScanHistory } from './components/ScanHistory';
import { ScoreTrendChart, TrendPoint } from './components/ScoreTrendChart';
import { Shield, AlertCircle, RefreshCw } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8787';

// Fallback initial dataset in case backend is loading or cold-booting
const DEMO_FALLBACK_RESULT: ScanResult = {
  scan_id: 'demo-initial-scan',
  timestamp: new Date().toISOString(),
  target_path: './demo-vulnerable-app',
  summary: {
    total_findings: 18,
    critical_count: 8,
    high_count: 6,
    medium_count: 3,
    low_count: 1,
    files_scanned: 9,
    lines_scanned: 210,
    scan_duration_ms: 124.5,
    security_score: 0,
    ship_status: 'BLOCKED',
    owasp_breakdown: {
      'A03:2021-Injection': 6,
      'A07:2021-Identification and Authentication Failures': 4,
      'A06:2021-Vulnerable and Outdated Components': 4,
      'A05:2021-Security Misconfiguration': 3,
      'A02:2021-Cryptographic Failures': 1,
    },
    category_breakdown: {
      SECRETS: 4,
      SAST: 7,
      SCA: 4,
      IAC: 3,
    },
  },
  findings: [
    {
      id: 'f-1',
      rule_id: 'SEC-001',
      title: 'Hardcoded AWS Access Key ID',
      category: 'SECRETS',
      severity: 'CRITICAL',
      file_path: 'app.py',
      line_start: 11,
      line_end: 11,
      code_snippet: 'AWS_ACCESS_KEY_ID = "AKIA1111222233334444"',
      owasp_category: 'A07:2021-Identification and Authentication Failures',
      cwe_id: 'CWE-798',
      description: 'Hardcoded AWS access key detected. An attacker can use this key to access cloud resources.',
      remediation: 'Store AWS credentials in environment variables or use AWS IAM Roles.',
      auto_fix_hint: 'os.environ.get("AWS_ACCESS_KEY_ID")',
    },
    {
      id: 'f-2',
      rule_id: 'SAST-PY-001',
      title: 'SQL Injection via Dynamic String Formatting',
      category: 'SAST',
      severity: 'CRITICAL',
      file_path: 'app.py',
      line_start: 18,
      line_end: 18,
      code_snippet: 'query = f"SELECT * FROM users WHERE id = {user_id}"',
      owasp_category: 'A03:2021-Injection',
      cwe_id: 'CWE-89',
      description: 'SQL query formed using dynamic string interpolation inside execute(). Attackers can execute arbitrary SQL.',
      remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      auto_fix_hint: 'cursor.execute("SELECT ... WHERE id = %s", (val,))',
    },
    {
      id: 'f-3',
      rule_id: 'SAST-PY-002',
      title: 'Command Injection via os.system',
      category: 'SAST',
      severity: 'CRITICAL',
      file_path: 'app.py',
      line_start: 27,
      line_end: 27,
      code_snippet: 'os.system("ping -c 1 " + host)',
      owasp_category: 'A03:2021-Injection',
      cwe_id: 'CWE-78',
      description: 'Direct invocation of os.system allows command injection if arguments are influenced by external input.',
      remediation: 'Use subprocess.run(["ping", "-c", "1", host], check=True) with an argument list.',
      auto_fix_hint: 'subprocess.run(["cmd", arg], check=True)',
    },
    {
      id: 'f-4',
      rule_id: 'SCA-CVE20208203',
      title: 'Prototype Pollution in lodash (CVE-2020-8203)',
      category: 'SCA',
      severity: 'HIGH',
      file_path: 'package.json',
      line_start: 11,
      line_end: 11,
      code_snippet: '"lodash": "4.17.15"',
      owasp_category: 'A06:2021-Vulnerable and Outdated Components',
      cwe_id: 'CWE-1321',
      description: 'lodash before 4.17.21 is vulnerable to prototype pollution in zipObjectDeep.',
      remediation: 'Upgrade lodash to version 4.17.21 or higher.',
      auto_fix_hint: 'lodash@4.17.21',
    },
    {
      id: 'f-5',
      rule_id: 'IAC-DOCKER-001',
      title: 'Container Running as Root (Missing USER Instruction)',
      category: 'IAC',
      severity: 'HIGH',
      file_path: 'Dockerfile',
      line_start: 2,
      line_end: 14,
      code_snippet: 'USER nonroot (missing)',
      owasp_category: 'A05:2021-Security Misconfiguration',
      cwe_id: 'CWE-250',
      description: 'Dockerfile has no USER directive; container processes execute with full root privileges.',
      remediation: 'Add unprivileged user: RUN adduser -D appuser && USER appuser',
      auto_fix_hint: 'USER appuser',
    },
  ],
};

export const App: React.FC = () => {
  const [currentScan, setCurrentScan] = useState<ScanResult>(DEMO_FALLBACK_RESULT);
  const [scans, setScans] = useState<ScanResult[]>([DEMO_FALLBACK_RESULT]);
  const [trendData, setTrendData] = useState<TrendPoint[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Poll/check engine health and fetch recent scans
  const checkHealthAndLoad = async () => {
    try {
      const healthRes = await fetch(`${API_BASE}/api/health`, { method: 'GET' });
      if (healthRes.ok) {
        setBackendOnline(true);
        setErrorMsg(null);

        const scansRes = await fetch(`${API_BASE}/api/scans`);
        if (scansRes.ok) {
          const list: ScanResult[] = await scansRes.json();
          if (list && list.length > 0) {
            setScans(list);
            setCurrentScan(list[0]);
          } else {
            // Trigger automatic initial scan of demo app if history is empty
            await handleRunScan('./demo-vulnerable-app');
          }
        }

        const historyRes = await fetch(`${API_BASE}/api/history`);
        if (historyRes.ok) {
          const trendList: TrendPoint[] = await historyRes.json();
          setTrendData(trendList);
        }
      } else {
        setBackendOnline(false);
      }
    } catch {
      setBackendOnline(false);
    }
  };

  useEffect(() => {
    checkHealthAndLoad();
    const interval = setInterval(checkHealthAndLoad, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleRunScan = async (targetPath: string, customMinScore?: number) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path: targetPath,
          min_score: customMinScore !== undefined ? customMinScore : 80,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: 'Scan request failed' }));
        throw new Error(errorData.detail || `Server returned ${res.status}`);
      }

      const result: ScanResult = await res.json();
      setCurrentScan(result);
      setScans((prev) => [result, ...prev.filter((s) => s.scan_id !== result.scan_id)]);
      setBackendOnline(true);
    } catch (err) {
      console.warn('API error during scan:', err);
      setErrorMsg(`Engine scan request failed: ${err instanceof Error ? err.message : String(err)}. Make sure the engine server is running (secureship serve --port 8787).`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunGitHubScan = async (repoUrl: string) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/scan/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl }),
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: 'GitHub scan failed' }));
        throw new Error(errorData.detail || `Server returned ${res.status}`);
      }

      const result: ScanResult = await res.json();
      setCurrentScan(result);
      setScans((prev) => [result, ...prev.filter((s) => s.scan_id !== result.scan_id)]);
      setBackendOnline(true);
      checkHealthAndLoad();
    } catch (err) {
      console.warn('API error during GitHub scan:', err);
      setErrorMsg(`GitHub Scan Failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUploadZipScan = async (file: File) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch(`${API_BASE}/api/scan/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({ detail: 'Zip scan upload failed' }));
        throw new Error(errorData.detail || `Server returned ${res.status}`);
      }

      const result: ScanResult = await res.json();
      setCurrentScan(result);
      setScans((prev) => [result, ...prev.filter((s) => s.scan_id !== result.scan_id)]);
      setBackendOnline(true);
      checkHealthAndLoad();
    } catch (err) {
      console.warn('API error during upload scan:', err);
      setErrorMsg(`Archive Scan Failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      <Header
        onRunScan={handleRunScan}
        onRunGitHubScan={handleRunGitHubScan}
        onUploadZipScan={handleUploadZipScan}
        isLoading={isLoading}
        backendOnline={backendOnline}
        targetPath={currentScan.target_path}
        onRefresh={checkHealthAndLoad}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 md:px-6 py-8 space-y-6">
        {/* Error Notification if backend offline */}
        {errorMsg && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 text-amber-400" />
            <div className="flex-1">{errorMsg}</div>
            <button
              onClick={() => handleRunScan(currentScan.target_path)}
              className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 font-semibold cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        {/* Ship-Readiness Banner & Security Score Gauge */}
        <ShipBanner
          status={currentScan.summary.ship_status}
          score={currentScan.summary.security_score}
          criticalCount={currentScan.summary.critical_count}
          totalFindings={currentScan.summary.total_findings}
        />

        {/* KPI Grid */}
        <KpiGrid summary={currentScan.summary} />

        {/* Scan History Bar */}
        <ScanHistory
          scans={scans}
          currentScanId={currentScan.scan_id}
          onSelectScan={(s) => setCurrentScan(s)}
        />

        {/* Persistent Score Trend Chart */}
        <ScoreTrendChart trendData={trendData} />

        {/* Severity Distribution & OWASP Mapping */}
        <SeverityCharts summary={currentScan.summary} />

        {/* Interactive Findings Explorer */}
        <FindingsTable findings={currentScan.findings} />
      </main>

      {/* Footer */}
      <footer className="border-t border-cyber-border py-6 px-6 text-center text-xs text-slate-500 bg-[#060910]">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-slate-400 font-semibold">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>SecureShip Shift-Left Platform</span>
          </div>
          <div>OWASP Top 10 • CWE Matrix • Real-Time DevSecOps Quality Gate</div>
          <div className="font-mono text-slate-600">CLI • VS Code • Web Dashboard</div>
        </div>
      </footer>
    </div>
  );
};
