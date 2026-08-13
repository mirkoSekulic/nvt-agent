"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const extension = require("./extension.js");

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nvt-agent-terminal-test-"));
process.on("exit", () => fs.rmSync(directory, { recursive: true, force: true }));
const missingMarker = path.join(directory, "missing");
const enabledMarker = path.join(directory, "enabled");
const malformedMarker = path.join(directory, "malformed");
fs.writeFileSync(enabledMarker, "enabled\n", { mode: 0o600 });
fs.writeFileSync(malformedMarker, "unexpected\n", { mode: 0o600 });

function fixture(existingTerminals = []) {
  const created = [];
  const calls = [];
  const vscode = {
    window: {
      terminals: existingTerminals,
      createTerminal(options) {
        calls.push(["createTerminal", options]);
        const terminal = {
          name: options.name,
          creationOptions: options,
          show(preserveFocus) {
            calls.push(["show", preserveFocus]);
          },
        };
        created.push(terminal);
        return terminal;
      },
    },
  };
  return { vscode, calls, created };
}

{
  const { vscode, calls } = fixture();
  assert.strictEqual(extension.activate({}, vscode, missingMarker), undefined);
  assert.deepStrictEqual(calls, []);
}

assert.throws(
  () => extension.activate({}, fixture().vscode, malformedMarker),
  /enable marker is invalid/,
);

{
  const { vscode, calls, created } = fixture();
  const terminal = extension.activate({}, vscode, enabledMarker);
  assert.strictEqual(terminal, created[0]);
  assert.deepStrictEqual(calls, [
    [
      "createTerminal",
      {
        name: "NVT Agent Session",
        shellPath: "nvt-session-attach",
      },
    ],
    ["show", false],
  ]);
}

{
  const calls = [];
  const existing = {
    name: "NVT Agent Session",
    creationOptions: { shellPath: "nvt-session-attach" },
    show(preserveFocus) {
      calls.push(["show", preserveFocus]);
    },
  };
  const { vscode } = fixture([existing]);
  vscode.window.createTerminal = () => {
    throw new Error("activation created a duplicate agent terminal");
  };
  assert.strictEqual(extension.activate({}, vscode, enabledMarker), existing);
  assert.deepStrictEqual(calls, [["show", false]]);
}

{
  const sameNameUserTerminal = {
    name: "NVT Agent Session",
    creationOptions: { shellPath: "/bin/bash" },
    show() {
      throw new Error("activation reused a same-name user terminal");
    },
  };
  const { vscode, created } = fixture([sameNameUserTerminal]);
  assert.strictEqual(extension.activate({}, vscode, enabledMarker), created[0]);
}

assert.strictEqual(
  extension.enableMarkerPath({ NVT_STATE_DIR: "/state" }),
  path.join("/state", "code-server-agent-terminal-enabled"),
);

const source = fs.readFileSync(path.join(__dirname, "extension.js"), "utf8");
for (const forbidden of [
  "task.allowAutomaticTasks",
  "executeTask",
  "fetchTasks",
  ".vscode/tasks.json",
  "getConfiguration",
  "tmux",
]) {
  assert.strictEqual(source.includes(forbidden), false, `forbidden activation behavior: ${forbidden}`);
}

console.log("code-server agent terminal activation test passed");
