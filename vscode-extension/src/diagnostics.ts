import * as vscode from 'vscode';
import { Finding, Severity } from './types';

export interface SecureShipDiagnostic extends vscode.Diagnostic {
  finding: Finding;
}

export class DiagnosticsManager {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('secureship');
  }

  public getCollection(): vscode.DiagnosticCollection {
    return this.diagnosticCollection;
  }

  public updateDiagnostics(uri: vscode.Uri, findings: Finding[], minSeverity: string = 'LOW'): void {
    const minWeight = this.getSeverityWeight(minSeverity as Severity);
    const diagnostics: SecureShipDiagnostic[] = [];

    for (const f of findings) {
      if (this.getSeverityWeight(f.severity) < minWeight) {
        continue;
      }

      const startLine = Math.max(0, f.line_start - 1);
      const endLine = Math.max(startLine, f.line_end - 1);
      const range = new vscode.Range(startLine, 0, endLine, 999);

      const vsSeverity = this.mapSeverity(f.severity);
      const message = `[${f.rule_id}] ${f.title}\n${f.description}\nRemediation: ${f.remediation}`;

      const diagnostic = new vscode.Diagnostic(range, message, vsSeverity) as SecureShipDiagnostic;
      diagnostic.code = f.rule_id;
      diagnostic.source = `SecureShip (${f.cwe_id})`;
      diagnostic.finding = f;

      diagnostics.push(diagnostic);
    }

    this.diagnosticCollection.set(uri, diagnostics);
  }

  public clearForUri(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  public clearAll(): void {
    this.diagnosticCollection.clear();
  }

  public dispose(): void {
    this.diagnosticCollection.dispose();
  }

  private mapSeverity(sev: Severity): vscode.DiagnosticSeverity {
    switch (sev) {
      case 'CRITICAL':
      case 'HIGH':
        return vscode.DiagnosticSeverity.Error;
      case 'MEDIUM':
        return vscode.DiagnosticSeverity.Warning;
      case 'LOW':
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  private getSeverityWeight(sev: Severity): number {
    switch (sev) {
      case 'CRITICAL':
        return 4;
      case 'HIGH':
        return 3;
      case 'MEDIUM':
        return 2;
      case 'LOW':
        return 1;
      default:
        return 0;
    }
  }
}
