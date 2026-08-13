"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const TERMINAL_NAME = "NVT Agent Session";
const SESSION_ATTACH_COMMAND = "nvt-session-attach";
const ENABLE_MARKER = "code-server-agent-terminal-enabled";
const ENABLE_MARKER_CONTENT = "enabled\n";

function enableMarkerPath(environment = process.env) {
  const stateDir = environment.NVT_STATE_DIR || path.join(os.homedir(), ".nvt-agent");
  return path.join(stateDir, ENABLE_MARKER);
}

function enabledByMarker(markerPath) {
  let content;
  try {
    content = fs.readFileSync(markerPath, "utf8");
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }
    throw new Error("NVT agent terminal enable marker could not be read");
  }
  if (content !== ENABLE_MARKER_CONTENT) {
    throw new Error("NVT agent terminal enable marker is invalid");
  }
  return true;
}

function isManagedTerminal(candidate) {
  return (
    candidate.name === TERMINAL_NAME &&
    candidate.creationOptions &&
    candidate.creationOptions.shellPath === SESSION_ATTACH_COMMAND
  );
}

function openAgentTerminal(vscode, markerPath = enableMarkerPath()) {
  if (!enabledByMarker(markerPath)) {
    return undefined;
  }

  let terminal = vscode.window.terminals.find(isManagedTerminal);
  if (terminal === undefined) {
    terminal = vscode.window.createTerminal({
      name: TERMINAL_NAME,
      shellPath: SESSION_ATTACH_COMMAND,
    });
  }

  // preserveFocus=false reveals the integrated terminal panel and focuses the
  // dedicated agent terminal. No terminal profile or workspace task is used.
  terminal.show(false);
  return terminal;
}

function activate(_context, vscodeOverride, markerPathOverride) {
  const vscode = vscodeOverride || require("vscode");
  return openAgentTerminal(vscode, markerPathOverride || enableMarkerPath());
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  enabledByMarker,
  enableMarkerPath,
  isManagedTerminal,
  openAgentTerminal,
};
