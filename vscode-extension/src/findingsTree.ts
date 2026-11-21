import * as vscode from 'vscode';
import * as path from 'path';
import { Finding, Severity } from './types';

export class TreeItemNode extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue: string,
    public readonly finding?: Finding,
    public readonly severityGroup?: Severity,
    public readonly filePathGroup?: string
  ) {
    super(label, collapsibleState);
  }
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItemNode> {
  private _onDidChangeTreeData: vscode.EventEmitter<TreeItemNode | undefined | void> =
    new vscode.EventEmitter<TreeItemNode | undefined | void>();
  readonly onDidChangeTreeData: vscode.Event<TreeItemNode | undefined | void> =
    this._onDidChangeTreeData.event;

  private findings: Finding[] = [];

  public refresh(findings: Finding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: TreeItemNode): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: TreeItemNode): Thenable<TreeItemNode[]> {
    if (!this.findings || this.findings.length === 0) {
      return Promise.resolve([
        new TreeItemNode('✅ No security findings detected', vscode.TreeItemCollapsibleState.None, 'empty'),
      ]);
    }

    // Top-level: Severity Groups
    if (!element) {
      const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      const nodes: TreeItemNode[] = [];

      for (const sev of severities) {
        const count = this.findings.filter((f) => f.severity === sev).length;
        if (count > 0) {
          const node = new TreeItemNode(
            `${sev} (${count})`,
            vscode.TreeItemCollapsibleState.Expanded,
            'severityGroup',
            undefined,
            sev
          );
          node.iconPath = this.getSeverityIcon(sev);
          nodes.push(node);
        }
      }

      return Promise.resolve(nodes);
    }

    // Second level: Group by file within Severity Group
    if (element.contextValue === 'severityGroup' && element.severityGroup) {
      const sev = element.severityGroup;
      const sevFindings = this.findings.filter((f) => f.severity === sev);

      // Group by file
      const fileMap = new Map<string, Finding[]>();
      for (const f of sevFindings) {
        const list = fileMap.get(f.file_path) || [];
        list.push(f);
        fileMap.set(f.file_path, list);
      }

      const fileNodes: TreeItemNode[] = [];
      for (const [filePath, fList] of fileMap.entries()) {
        const node = new TreeItemNode(
          `${path.basename(filePath)} (${fList.length})`,
          vscode.TreeItemCollapsibleState.Expanded,
          'fileGroup',
          undefined,
          sev,
          filePath
        );
        node.description = path.dirname(filePath);
        node.iconPath = vscode.ThemeIcon.File;
        fileNodes.push(node);
      }

      return Promise.resolve(fileNodes);
    }

    // Third level: Findings list for file
    if (element.contextValue === 'fileGroup' && element.severityGroup && element.filePathGroup) {
      const sev = element.severityGroup;
      const fPath = element.filePathGroup;
      const fileFindings = this.findings.filter((f) => f.severity === sev && f.file_path === fPath);

      const items = fileFindings.map((f) => {
        const item = new TreeItemNode(
          `[${f.rule_id}] ${f.title}`,
          vscode.TreeItemCollapsibleState.None,
          'findingItem',
          f
        );
        item.description = `Line ${f.line_start}`;
        item.tooltip = new vscode.MarkdownString(
          `**${f.title}**\n\n${f.description}\n\n*Remediation:* ${f.remediation}\n\n*CWE:* ${f.cwe_id} | *OWASP:* ${f.owasp_category}`
        );

        const targetUri = path.isAbsolute(f.file_path)
          ? vscode.Uri.file(f.file_path)
          : (vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
              ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, f.file_path)
              : vscode.Uri.file(f.file_path));

        // Command to jump to file & line
        item.command = {
          command: 'vscode.open',
          title: 'Open Finding',
          arguments: [
            targetUri,
            {
              selection: new vscode.Range(
                Math.max(0, f.line_start - 1),
                0,
                Math.max(0, f.line_end - 1),
                100
              ),
            },
          ],
        };

        return item;
      });

      return Promise.resolve(items);
    }

    return Promise.resolve([]);
  }

  private getSeverityIcon(sev: Severity): vscode.ThemeIcon {
    switch (sev) {
      case 'CRITICAL':
        return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
      case 'HIGH':
        return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
      case 'MEDIUM':
        return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
      case 'LOW':
      default:
        return new vscode.ThemeIcon('shield');
    }
  }
}
