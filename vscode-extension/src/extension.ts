import * as vscode from 'vscode';
import * as path from 'path';
import { ScannerClient, AdvisorAdvice } from './scannerClient';
import { DiagnosticsManager } from './diagnostics';
import { SecureShipQuickFixProvider } from './quickFixes';
import { FindingsTreeProvider } from './findingsTree';
import { StatusBarManager } from './statusBar';
import { Finding, Severity } from './types';

let diagnosticsManager: DiagnosticsManager;
let statusBarManager: StatusBarManager;
let treeProvider: FindingsTreeProvider;
let scannerClient: ScannerClient;
const allFindingsMap = new Map<string, Finding[]>();

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration('secureship');
  const serverUrl = config.get<string>('serverUrl', 'http://127.0.0.1:8787');
  const minSeverity = config.get<string>('minSeverity', 'LOW');
  const minScore = config.get<number>('minScore', 80);

  scannerClient = new ScannerClient(serverUrl);
  diagnosticsManager = new DiagnosticsManager();
  statusBarManager = new StatusBarManager();
  treeProvider = new FindingsTreeProvider();

  // Register Tree View in Sidebar Activity Bar
  vscode.window.registerTreeDataProvider('secureship.findingsView', treeProvider);

  // Register Code Action Quick Fix Provider for all languages
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new SecureShipQuickFixProvider(),
      {
        providedCodeActionKinds: SecureShipQuickFixProvider.providedCodeActionKinds,
      }
    )
  );

  // Command: Scan Current File
  const scanCurrentFileCmd = vscode.commands.registerCommand(
    'secureship.scanCurrentFile',
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('SecureShip: No active file to scan.');
        return;
      }
      await scanDocument(editor.document);
    }
  );

  // Command: Scan Workspace
  const scanWorkspaceCmd = vscode.commands.registerCommand(
    'secureship.scanWorkspace',
    async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('SecureShip: No open workspace folder to scan.');
        return;
      }

      statusBarManager.showScanning();
      vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'SecureShip: Scanning workspace for security vulnerabilities...',
          cancellable: false,
        },
        async () => {
          try {
            const rootPath = folders[0].uri.fsPath;
            const currentMinScore = vscode.workspace.getConfiguration('secureship').get<number>('minScore', minScore);
            const result = await scannerClient.scanWorkspace(rootPath, minSeverity, currentMinScore);

            diagnosticsManager.clearAll();
            allFindingsMap.clear();

            // Group by file and update diagnostics
            for (const finding of result.findings) {
              const fileUri = path.isAbsolute(finding.file_path)
                ? vscode.Uri.file(finding.file_path)
                : vscode.Uri.joinPath(folders[0].uri, finding.file_path);

              const list = allFindingsMap.get(fileUri.toString()) || [];
              list.push(finding);
              allFindingsMap.set(fileUri.toString(), list);
            }

            for (const [uriStr, fList] of allFindingsMap.entries()) {
              diagnosticsManager.updateDiagnostics(vscode.Uri.parse(uriStr), fList, minSeverity);
            }

            treeProvider.refresh(result.findings);
            statusBarManager.updateScore(
              result.summary.security_score,
              result.summary.ship_status,
              result.summary.critical_count,
              result.summary.high_count
            );

            if (result.summary.ship_status === 'BLOCKED') {
              vscode.window.showErrorMessage(
                `SecureShip Gate: Project is BLOCKED from shipping! (${result.summary.total_findings} findings, score ${result.summary.security_score}/100)`
              );
            } else if (result.summary.ship_status === 'READY TO SHIP') {
              vscode.window.showInformationMessage(
                `SecureShip Gate: Project is READY TO SHIP! (Security Score: ${result.summary.security_score}/100)`
              );
            } else {
              vscode.window.showWarningMessage(
                `SecureShip Gate: Project NEEDS REVIEW (Score: ${result.summary.security_score}/100)`
              );
            }
          } catch (err) {
            handleScanFailure(err);
          }
        }
      );
    }
  );

  // Command: Open Dashboard
  const openDashboardCmd = vscode.commands.registerCommand(
    'secureship.openDashboard',
    async () => {
      const dashboardUrl = 'http://localhost:5173';
      const fallbackReportUrl = `${serverUrl}/api/report/html`;

      try {
        await vscode.env.openExternal(vscode.Uri.parse(dashboardUrl));
      } catch {
        await vscode.env.openExternal(vscode.Uri.parse(fallbackReportUrl));
      }
    }
  );

  // Command: Explain Finding with AI Advisor
  const explainFindingCmd = vscode.commands.registerCommand(
    'secureship.explainFinding',
    async (finding: Finding) => {
      if (!finding) {
        return;
      }

      vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `SecureShip AI Advisor: Analyzing ${finding.rule_id}...`,
        },
        async () => {
          const advice = await scannerClient.explainFinding(finding);
          showAdviceWebview(finding, advice);
        }
      );
    }
  );

  // Command: Install Git Security Gates (Pre-Commit & Pre-Push)
  const installHooksCmd = vscode.commands.registerCommand(
    'secureship.installHooks',
    async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('SecureShip: Open a Git workspace folder first.');
        return;
      }
      const terminal = vscode.window.createTerminal('SecureShip Security Gates');
      terminal.show();
      terminal.sendText('secureship install-hook');
      vscode.window.showInformationMessage(
        'SecureShip: Installing Git Pre-Commit & Pre-Push security gates in workspace...'
      );
    }
  );

  // Command: Emergency Bypass & Push
  const bypassPushCmd = vscode.commands.registerCommand(
    'secureship.bypassPush',
    async () => {
      const confirmation = await vscode.window.showWarningMessage(
        '⚠️ Are you sure you want to authorize an Emergency Security Bypass for git push?',
        { modal: true },
        'Authorize & Push',
        'Cancel'
      );
      if (confirmation === 'Authorize & Push') {
        const terminal = vscode.window.createTerminal('SecureShip Bypass');
        terminal.show();
        terminal.sendText('secureship bypass --push');
      }
    }
  );

  // Real-time scan on file save
  const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (doc) => {
    const scanOnSave = vscode.workspace.getConfiguration('secureship').get<boolean>('scanOnSave', true);
    if (scanOnSave) {
      await scanDocument(doc);
    }
  });

  // Re-read configuration changes
  const configListener = vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration('secureship')) {
      const newConfig = vscode.workspace.getConfiguration('secureship');
      const newServerUrl = newConfig.get<string>('serverUrl', 'http://127.0.0.1:8787');
      scannerClient.setServerUrl(newServerUrl);
    }
  });

  context.subscriptions.push(
    scanCurrentFileCmd,
    scanWorkspaceCmd,
    openDashboardCmd,
    explainFindingCmd,
    installHooksCmd,
    bypassPushCmd,
    onSaveListener,
    configListener,
    diagnosticsManager,
    statusBarManager
  );

  // Initial workspace scan if workspace is open
  if (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
    vscode.commands.executeCommand('secureship.scanWorkspace');
  }
}

async function handleScanFailure(err: unknown): Promise<void> {
  const errMsg = err instanceof Error ? err.message : String(err);
  const choice = await vscode.window.showWarningMessage(
    `SecureShip: Local engine API at http://127.0.0.1:8787 is not responding (${errMsg}).`,
    'Start Engine Server',
    'Retry Scan'
  );

  if (choice === 'Start Engine Server') {
    const terminal = vscode.window.createTerminal('SecureShip Engine');
    terminal.show();
    terminal.sendText('secureship serve --port 8787');
  } else if (choice === 'Retry Scan') {
    vscode.commands.executeCommand('secureship.scanWorkspace');
  }
  statusBarManager.updateScore(100, 'READY TO SHIP', 0, 0);
}

function showAdviceWebview(finding: Finding, advice: AdvisorAdvice): void {
  const panel = vscode.window.createWebviewPanel(
    'secureshipAdvice',
    `🛡️ Advisor: ${finding.rule_id}`,
    vscode.ViewColumn.Beside,
    { enableScripts: true }
  );

  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; line-height: 1.6; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
    h2 { margin-top: 0; color: var(--vscode-textLink-foreground); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }
    .card { background: var(--vscode-editor-inactiveSelectionBackground); border: 1px solid var(--vscode-widget-border); border-radius: 8px; padding: 14px; margin-bottom: 16px; }
    .title { font-weight: bold; margin-bottom: 6px; }
    pre { background: var(--vscode-textCodeBlock-background); padding: 12px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 12px; }
    button { background: var(--vscode-button-background); color: var(--vscode-button-foreground); border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: bold; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    .provider-tag { font-size: 11px; opacity: 0.7; margin-top: 10px; }
  </style>
</head>
<body>
  <h2>🛡️ ${finding.title}</h2>
  <p><span class="badge">${finding.severity}</span> <code>${finding.rule_id}</code> | <strong>Location:</strong> ${finding.file_path}:${finding.line_start}</p>

  <div class="card">
    <div class="title">🔍 Root Cause & Security Analysis</div>
    <div>${advice.analysis}</div>
  </div>

  <div class="card">
    <div class="title">⚡ Attack Vector & Exploit Scenario</div>
    <div>${advice.exploit_scenario}</div>
  </div>

  <div class="card">
    <div class="title">💡 Secure Remediation Strategy</div>
    <div>${advice.remediation_strategy}</div>
  </div>

  <div class="card">
    <div class="title">✨ Context-Aware Patched Code</div>
    <pre><code>${advice.patched_code}</code></pre>
  </div>

  <div class="provider-tag">Generated by: ${advice.provider}</div>
</body>
</html>`;
}

async function scanDocument(document: vscode.TextDocument): Promise<void> {
  if (document.uri.scheme !== 'file') {
    return;
  }

  const minSeverity = vscode.workspace.getConfiguration('secureship').get<string>('minSeverity', 'LOW');

  try {
    const findings = await scannerClient.scanContent(document.fileName, document.getText());
    diagnosticsManager.updateDiagnostics(document.uri, findings, minSeverity);

    allFindingsMap.set(document.uri.toString(), findings);

    const aggregated: Finding[] = [];
    for (const fList of allFindingsMap.values()) {
      aggregated.push(...fList);
    }

    treeProvider.refresh(aggregated);

    const criticals = aggregated.filter((f) => f.severity === 'CRITICAL').length;
    const highs = aggregated.filter((f) => f.severity === 'HIGH').length;
    let score = 100;
    for (const f of aggregated) {
      if (f.severity === 'CRITICAL') score -= 25;
      else if (f.severity === 'HIGH') score -= 15;
      else if (f.severity === 'MEDIUM') score -= 5;
      else if (f.severity === 'LOW') score -= 2;
    }
    score = Math.max(0, score);
    const status = (criticals > 0 || score < 50) ? 'BLOCKED' : (score >= 80 ? 'READY TO SHIP' : 'NEEDS REVIEW');
    statusBarManager.updateScore(score, status, criticals, highs);
  } catch (err) {
    console.error('SecureShip on-save scan error:', err);
  }
}

export function deactivate() {
  if (diagnosticsManager) {
    diagnosticsManager.dispose();
  }
  if (statusBarManager) {
    statusBarManager.dispose();
  }
}
