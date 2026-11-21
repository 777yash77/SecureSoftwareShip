import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { exec } from 'child_process';
import { Finding, ScanResult } from './types';

export interface AdvisorAdvice {
  rule_id: string;
  title: string;
  analysis: string;
  exploit_scenario: string;
  remediation_strategy: string;
  patched_code: string;
  provider: string;
}

export class ScannerClient {
  private serverUrl: string;

  constructor(serverUrl: string = 'http://127.0.0.1:8787') {
    this.serverUrl = serverUrl.replace(/\/+$/, '');
  }

  public setServerUrl(url: string): void {
    this.serverUrl = url.replace(/\/+$/, '');
  }

  public async checkHealth(): Promise<boolean> {
    try {
      const res = await this.httpRequest<{ status: string }>(
        `${this.serverUrl}/api/health`,
        'GET'
      );
      return res.status === 'ok';
    } catch {
      return false;
    }
  }

  /**
   * Scans document content on the fly via FastAPI backend, or falls back to CLI if offline.
   */
  public async scanContent(filePath: string, content: string): Promise<Finding[]> {
    try {
      const payload = JSON.stringify({ file_path: filePath, content });
      const response = await this.httpRequest<Finding[]>(
        `${this.serverUrl}/api/scan/content`,
        'POST',
        payload
      );
      return response;
    } catch {
      // If server is not running, fall back to CLI scan
      return this.scanViaCli(filePath);
    }
  }

  /**
   * Scans entire workspace or directory.
   */
  public async scanWorkspace(
    workspacePath: string,
    minSeverity: string = 'LOW',
    minScore: number = 80
  ): Promise<ScanResult> {
    try {
      const payload = JSON.stringify({
        path: workspacePath,
        min_severity: minSeverity,
        min_score: minScore,
      });
      return await this.httpRequest<ScanResult>(
        `${this.serverUrl}/api/scan`,
        'POST',
        payload
      );
    } catch {
      return this.scanWorkspaceViaCli(workspacePath, minScore);
    }
  }

  /**
   * Request AI / Expert explanation and patch for finding.
   */
  public async explainFinding(finding: Finding, contextCode?: string): Promise<AdvisorAdvice> {
    try {
      const payload = JSON.stringify({ finding, code_context: contextCode });
      return await this.httpRequest<AdvisorAdvice>(
        `${this.serverUrl}/api/explain`,
        'POST',
        payload
      );
    } catch {
      return {
        rule_id: finding.rule_id,
        title: finding.title,
        analysis: `${finding.description} Class: ${finding.cwe_id} / ${finding.owasp_category}.`,
        exploit_scenario: 'Exploitation allows attackers to compromise application integrity or data confidentiality.',
        remediation_strategy: finding.remediation,
        patched_code: finding.auto_fix_hint || '# Review remediation guidelines',
        provider: 'SecureShip Client Fallback Advisor',
      };
    }
  }

  private httpRequest<T>(endpoint: string, method: string, data?: string): Promise<T> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(endpoint);
      const isHttps = parsedUrl.protocol === 'https:';
      const client = isHttps ? https : http;

      const options: http.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data ? Buffer.byteLength(data) : 0,
        },
        timeout: 4000,
      };

      const req = client.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(body) as T);
            } catch (e) {
              reject(e);
            }
          } else {
            reject(new Error(`Server responded with ${res.statusCode}: ${body}`));
          }
        });
      });

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });

      if (data) {
        req.write(data);
      }
      req.end();
    });
  }

  private scanViaCli(filePath: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      const cmd = `secureship scan "${filePath}" --format json`;
      exec(cmd, { timeout: 10000 }, (error, stdout) => {
        if (!stdout) {
          resolve([]);
          return;
        }
        try {
          const res = JSON.parse(stdout) as ScanResult;
          resolve(res.findings || []);
        } catch {
          resolve([]);
        }
      });
    });
  }

  private scanWorkspaceViaCli(workspacePath: string, minScore: number = 80): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const cmd = `secureship scan "${workspacePath}" --format json --modify-score ${minScore}`;
      exec(cmd, { timeout: 25000 }, (error, stdout) => {
        if (!stdout) {
          reject(new Error('CLI execution produced no output'));
          return;
        }
        try {
          const res = JSON.parse(stdout) as ScanResult;
          resolve(res);
        } catch (e) {
          reject(e);
        }
      });
    });
  }
}
