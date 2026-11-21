import * as vscode from 'vscode';
import { SecureShipDiagnostic } from './diagnostics';

export class SecureShipQuickFixProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      const shipDiag = diagnostic as SecureShipDiagnostic;
      let ruleId = '';
      if (typeof diagnostic.code === 'string') {
        ruleId = diagnostic.code;
      } else if (typeof diagnostic.code === 'object' && diagnostic.code !== null && 'value' in diagnostic.code) {
        ruleId = String(diagnostic.code.value);
      }
      const lineIndex = diagnostic.range.start.line;
      const lineText = document.lineAt(lineIndex).text;

      // Quick Fix 1: Precise Replace MD5/SHA1 with SHA-256 (Rule SAST-PY-007)
      const cryptoMatch = /hashlib\.(md5|sha1)/.exec(lineText);
      if (ruleId === 'SAST-PY-007' || cryptoMatch) {
        const fix = new vscode.CodeAction(
          '🔒 Upgrade weak hash to hashlib.sha256()',
          vscode.CodeActionKind.QuickFix
        );
        fix.edit = new vscode.WorkspaceEdit();
        if (cryptoMatch) {
          const startCol = cryptoMatch.index;
          const endCol = startCol + cryptoMatch[0].length;
          const targetRange = new vscode.Range(lineIndex, startCol, lineIndex, endCol);
          fix.edit.replace(document.uri, targetRange, 'hashlib.sha256');
        } else {
          const newLine = lineText.replace(/hashlib\.(md5|sha1)/g, 'hashlib.sha256');
          fix.edit.replace(document.uri, document.lineAt(lineIndex).range, newLine);
        }
        fix.isPreferred = true;
        fix.diagnostics = [diagnostic];
        actions.push(fix);
      }

      // Quick Fix 2: Replace Hardcoded Secret with Environment Variable (SEC-001, SEC-002, SEC-006)
      if (ruleId && (ruleId.startsWith('SEC-') || lineText.includes('AKIA') || lineText.includes('ghp_'))) {
        const isJs = document.languageId.includes('javascript') || document.languageId.includes('typescript');
        const envVarReplacement = isJs ? 'process.env.SECRET_KEY || ""' : 'os.environ.get("SECRET_KEY", "")';

        const fix = new vscode.CodeAction(
          `🔒 Replace secret literal with ${envVarReplacement}`,
          vscode.CodeActionKind.QuickFix
        );
        fix.edit = new vscode.WorkspaceEdit();

        const secretRegex = /(["'])(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{36,255}|[A-Za-z0-9_\-+=/.]{16,})\1/;
        const match = secretRegex.exec(lineText);
        if (match) {
          const startCol = match.index;
          const endCol = startCol + match[0].length;
          fix.edit.replace(document.uri, new vscode.Range(lineIndex, startCol, lineIndex, endCol), envVarReplacement);
        } else {
          const updatedLine = lineText.replace(secretRegex, envVarReplacement);
          fix.edit.replace(document.uri, document.lineAt(lineIndex).range, updatedLine);
        }
        fix.isPreferred = true;
        fix.diagnostics = [diagnostic];
        actions.push(fix);
      }

      // Quick Fix 3: Add USER nonroot to Dockerfile (IAC-DOCKER-001)
      if (ruleId === 'IAC-DOCKER-001' || document.fileName.toLowerCase().includes('dockerfile')) {
        const fix = new vscode.CodeAction(
          '🐳 Add unprivileged USER directive to Dockerfile',
          vscode.CodeActionKind.QuickFix
        );
        fix.edit = new vscode.WorkspaceEdit();

        // Find CMD or ENTRYPOINT line to insert before, otherwise append to end
        let targetLine = document.lineCount;
        for (let i = 0; i < document.lineCount; i++) {
          const text = document.lineAt(i).text.trim().toUpperCase();
          if (text.startsWith('CMD ') || text.startsWith('ENTRYPOINT ')) {
            targetLine = i;
            break;
          }
        }
        const insertPosition = new vscode.Position(targetLine, 0);
        fix.edit.insert(
          document.uri,
          insertPosition,
          '# Run container as unprivileged non-root user\nRUN adduser -D -u 10001 appuser && chown -R appuser /app\nUSER appuser\n\n'
        );
        fix.isPreferred = true;
        fix.diagnostics = [diagnostic];
        actions.push(fix);
      }

      // Quick Fix 4: Inline Suppression Comment (# secureship-ignore / // secureship-ignore)
      const isSlashComment = ['javascript', 'typescript', 'java', 'c', 'cpp', 'csharp', 'go', 'jsonc'].includes(
        document.languageId
      );
      const commentToken = isSlashComment ? `// secureship-ignore: ${ruleId || ''}` : `# secureship-ignore: ${ruleId || ''}`;

      const suppressAction = new vscode.CodeAction(
        `🛡️ Suppress with inline ${commentToken}`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.edit = new vscode.WorkspaceEdit();
      const endOfLine = new vscode.Position(lineIndex, lineText.length);
      suppressAction.edit.insert(document.uri, endOfLine, `  ${commentToken}`);
      suppressAction.diagnostics = [diagnostic];
      actions.push(suppressAction);

      // Upgrade 5: AI Advisor Quick Action
      if (shipDiag && shipDiag.finding) {
        const explainAction = new vscode.CodeAction(
          `✨ SecureShip: Explain with AI Advisor (${ruleId})`,
          vscode.CodeActionKind.QuickFix
        );
        explainAction.command = {
          command: 'secureship.explainFinding',
          title: 'Explain Finding with SecureShip AI Advisor',
          arguments: [shipDiag.finding],
        };
        explainAction.diagnostics = [diagnostic];
        actions.push(explainAction);
      }
    }

    return actions;
  }
}
