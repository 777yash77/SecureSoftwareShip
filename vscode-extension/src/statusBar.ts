import * as vscode from 'vscode';
import { ShipStatus } from './types';

export class StatusBarManager {
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = 'secureship.openDashboard';
    this.updateScore(100, 'READY TO SHIP', 0, 0);
    this.statusBarItem.show();
  }

  public updateScore(
    score: number,
    status: ShipStatus,
    criticalCount: number,
    highCount: number
  ): void {
    let icon = '$(shield)';
    let color: string | vscode.ThemeColor | undefined = undefined;

    if (status === 'READY TO SHIP') {
      color = '#10b981';
      icon = '$(shield)';
    } else if (status === 'NEEDS REVIEW') {
      color = new vscode.ThemeColor('statusBarItem.warningBackground');
      icon = '$(alert)';
    } else {
      color = new vscode.ThemeColor('statusBarItem.errorBackground');
      icon = '$(error)';
    }

    this.statusBarItem.text = `${icon} SecureShip: ${score}/100`;
    this.statusBarItem.backgroundColor = color instanceof vscode.ThemeColor ? color : undefined;
    this.statusBarItem.tooltip = new vscode.MarkdownString(
      `### 🛡️ SecureShip Security Gate\n\n` +
      `**Ship Status:** ${status}\n\n` +
      `**Security Score:** ${score}/100\n\n` +
      `- Critical Findings: ${criticalCount}\n` +
      `- High Findings: ${highCount}\n\n` +
      `*Click to open SecureShip Security Dashboard.*`
    );
  }

  public showScanning(): void {
    this.statusBarItem.text = `$(sync~spin) SecureShip: Scanning...`;
  }

  public dispose(): void {
    this.statusBarItem.dispose();
  }
}
