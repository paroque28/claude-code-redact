import * as vscode from "vscode";
import { execSync } from "child_process";
import * as path from "path";

interface RdxMatch {
  file: string;
  line: number;
  col: number;
  start: number;
  end: number;
  original: string;
  replacement: string;
  rule_id: string;
  category: string;
  description: string;
  action: string;
}

interface RdxCheckResult {
  matches: RdxMatch[];
  total: number;
}

// Decoration types
let secretDecoration: vscode.TextEditorDecorationType;
let replacementDecoration: vscode.TextEditorDecorationType;
let statusBarItem: vscode.StatusBarItem;

// Cache: file path → matches
const matchCache = new Map<string, RdxMatch[]>();

export function activate(context: vscode.ExtensionContext) {
  // Create decoration types
  secretDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(255, 80, 80, 0.15)",
    border: "1px solid rgba(255, 80, 80, 0.4)",
    borderRadius: "3px",
  });

  replacementDecoration = vscode.window.createTextEditorDecorationType({
    after: {
      color: "rgba(150, 150, 150, 0.7)",
      fontStyle: "italic",
      margin: "0 0 0 1em",
    },
  });

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBarItem.command = "rdx.scanFile";
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("rdx.toggleClaudeView", toggleClaudeView),
    vscode.commands.registerCommand("rdx.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) scanAndDecorate(editor);
    }),
    vscode.commands.registerCommand("rdx.refresh", refreshAll)
  );

  // Auto-scan on file open/save
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor && getConfig().autoScan) {
        scanAndDecorate(editor);
      }
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document === doc && getConfig().autoScan) {
        scanAndDecorate(editor);
      }
    })
  );

  // Scan current file on activation
  if (vscode.window.activeTextEditor && getConfig().autoScan) {
    scanAndDecorate(vscode.window.activeTextEditor);
  }

  // Hover provider — show redaction details
  context.subscriptions.push(
    vscode.languages.registerHoverProvider("*", {
      provideHover(document, position) {
        const matches = matchCache.get(document.uri.fsPath);
        if (!matches) return;

        const offset = document.offsetAt(position);
        const match = matches.find((m) => offset >= m.start && offset <= m.end);
        if (!match) return;

        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`**Redacted by rule:** \`${match.rule_id}\`\n\n`);
        md.appendMarkdown(`| | |\n|---|---|\n`);
        md.appendMarkdown(`| **Category** | ${match.category} |\n`);
        md.appendMarkdown(
          `| **Claude sees** | \`${match.replacement}\` |\n`
        );
        md.appendMarkdown(`| **Action** | ${match.action} |\n`);
        if (match.description) {
          md.appendMarkdown(`| **Description** | ${match.description} |\n`);
        }

        return new vscode.Hover(md);
      },
    })
  );

  // Diagnostics (problems panel)
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("rdx");
  context.subscriptions.push(diagnosticCollection);

  // Update diagnostics when scanning
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      updateDiagnostics(doc, diagnosticCollection);
    })
  );

  if (vscode.window.activeTextEditor) {
    updateDiagnostics(
      vscode.window.activeTextEditor.document,
      diagnosticCollection
    );
  }
}

function getConfig() {
  const config = vscode.workspace.getConfiguration("rdx");
  return {
    rdxPath: config.get<string>("rdxPath", "rdx"),
    autoScan: config.get<boolean>("autoScan", true),
    showInline: config.get<boolean>("showInlineReplacements", true),
  };
}

function runRdxCheck(filePath: string): RdxCheckResult | null {
  const config = getConfig();
  try {
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const stdout = execSync(
      `${config.rdxPath} check --json "${filePath}"`,
      {
        encoding: "utf-8",
        timeout: 10000,
        cwd: cwd,
      }
    );
    return JSON.parse(stdout);
  } catch (e: any) {
    // rdx check returns exit 1 when matches found — parse stdout from error
    if (e.stdout) {
      try {
        return JSON.parse(e.stdout);
      } catch {
        // fall through
      }
    }
    if (e.status !== 1) {
      console.error("rdx check failed:", e.message);
    }
    return null;
  }
}

function scanAndDecorate(editor: vscode.TextEditor) {
  const filePath = editor.document.uri.fsPath;
  const result = runRdxCheck(filePath);

  if (!result || result.total === 0) {
    editor.setDecorations(secretDecoration, []);
    editor.setDecorations(replacementDecoration, []);
    matchCache.delete(filePath);
    statusBarItem.text = "$(shield) rdx: clean";
    statusBarItem.tooltip = "No secrets detected";
    statusBarItem.show();
    return;
  }

  matchCache.set(filePath, result.matches);

  // Highlight secret values
  const secretRanges: vscode.DecorationOptions[] = [];
  const replacementRanges: vscode.DecorationOptions[] = [];

  for (const match of result.matches) {
    const startPos = editor.document.positionAt(match.start);
    const endPos = editor.document.positionAt(match.end);
    const range = new vscode.Range(startPos, endPos);

    secretRanges.push({ range });

    if (getConfig().showInline) {
      replacementRanges.push({
        range,
        renderOptions: {
          after: {
            contentText: ` → ${match.replacement}`,
          },
        },
      });
    }
  }

  editor.setDecorations(secretDecoration, secretRanges);
  editor.setDecorations(replacementDecoration, replacementRanges);

  // Status bar
  statusBarItem.text = `$(shield) rdx: ${result.total} redaction${result.total === 1 ? "" : "s"}`;
  statusBarItem.tooltip = `${result.total} value(s) will be redacted before reaching Claude`;
  statusBarItem.show();
}

function updateDiagnostics(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection
) {
  const matches = matchCache.get(document.uri.fsPath);
  if (!matches) {
    collection.delete(document.uri);
    return;
  }

  const diagnostics: vscode.Diagnostic[] = matches.map((match) => {
    const startPos = document.positionAt(match.start);
    const endPos = document.positionAt(match.end);
    const range = new vscode.Range(startPos, endPos);

    const severity =
      match.action === "block"
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Information;

    const diag = new vscode.Diagnostic(
      range,
      `[${match.rule_id}] ${match.description || "Will be redacted"} → ${match.replacement}`,
      severity
    );
    diag.source = "rdx";
    return diag;
  });

  collection.set(document.uri, diagnostics);
}

async function toggleClaudeView() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;

  const filePath = editor.document.uri.fsPath;
  const fileName = path.basename(filePath);
  const result = runRdxCheck(filePath);

  if (!result || result.total === 0) {
    vscode.window.showInformationMessage("No redactions in this file.");
    return;
  }

  // Build redacted version of the text
  let text = editor.document.getText();
  // Apply replacements in reverse order to preserve offsets
  const sorted = [...result.matches].sort((a, b) => b.start - a.start);
  for (const match of sorted) {
    text = text.slice(0, match.start) + match.replacement + text.slice(match.end);
  }

  // Show in a virtual document side-by-side
  const uri = vscode.Uri.parse(
    `rdx-claude-view:${fileName} (Claude's View)?${encodeURIComponent(text)}`
  );

  // Register a content provider for this scheme
  const provider = new (class implements vscode.TextDocumentContentProvider {
    provideTextDocumentContent(): string {
      return text;
    }
  })();

  const registration = vscode.workspace.registerTextDocumentContentProvider(
    "rdx-claude-view",
    provider
  );

  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, {
    viewColumn: vscode.ViewColumn.Beside,
    preserveFocus: true,
    preview: true,
  });

  // Clean up after a delay
  setTimeout(() => registration.dispose(), 60000);
}

function refreshAll() {
  matchCache.clear();
  for (const editor of vscode.window.visibleTextEditors) {
    scanAndDecorate(editor);
  }
}

export function deactivate() {
  matchCache.clear();
}
