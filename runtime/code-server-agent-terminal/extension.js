"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");

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
  // Restored terminals do not reliably retain creationOptions. The name is
  // the stable identity when metadata is absent. When VS Code does retain a
  // shell path, do not mistake a same-name ordinary shell for ours.
  if (candidate.name !== TERMINAL_NAME) {
    return false;
  }
  const shellPath = candidate.creationOptions && candidate.creationOptions.shellPath;
  return shellPath === undefined || shellPath === SESSION_ATTACH_COMMAND;
}

function claimAttachment(execFileSync = childProcess.execFileSync) {
  try {
    return execFileSync(SESSION_ATTACH_COMMAND, ["--claim"], {
      encoding: "utf8",
      timeout: 5000,
    }).trim();
  } catch (error) {
    if (error && error.status === 3) {
      return undefined;
    }
    throw error;
  }
}

function openAgentTerminal(vscode, markerPath = enableMarkerPath(), execFileSync) {
  if (!enabledByMarker(markerPath)) {
    return undefined;
  }

  let terminal = vscode.window.terminals.find(isManagedTerminal);
  if (terminal === undefined) {
    const claim = claimAttachment(execFileSync);
    if (claim === undefined) {
      return undefined;
    }
    terminal = vscode.window.createTerminal({
      name: TERMINAL_NAME,
      shellPath: SESSION_ATTACH_COMMAND,
      shellArgs: ["--attach", claim],
    });
  }

  // preserveFocus=false reveals the integrated terminal panel and focuses the
  // dedicated agent terminal. No terminal profile or workspace task is used.
  terminal.show(false);
  return terminal;
}

function activate(_context, vscodeOverride, markerPathOverride, execFileSyncOverride) {
  const vscode = vscodeOverride || require("vscode");
  return openAgentTerminal(vscode, markerPathOverride || enableMarkerPath(), execFileSyncOverride);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  enabledByMarker,
  enableMarkerPath,
  claimAttachment,
  isManagedTerminal,
  openAgentTerminal,
};
