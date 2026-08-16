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

function fixture(existingTerminals = [], claim = "test-claim\n") {
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
  const execFileSync = (command, args, options) => {
    calls.push(["execFileSync", command, args, options]);
    return claim;
  };
  return { vscode, calls, created, execFileSync };
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
  const { vscode, calls, created, execFileSync } = fixture();
  const terminal = extension.activate({}, vscode, enabledMarker, execFileSync);
  assert.strictEqual(terminal, created[0]);
  assert.deepStrictEqual(calls, [
    ["execFileSync", "nvt-session-attach", ["--claim"], { encoding: "utf8", timeout: 5000 }],
    [
      "createTerminal",
      {
        name: "NVT Agent Session",
        shellPath: "nvt-session-attach",
        shellArgs: ["--attach", "test-claim"],
      },
    ],
    ["show", false],
  ]);
}

{
  const calls = [];
  const existing = {
    name: "NVT Agent Session",
    creationOptions: {},
    show(preserveFocus) {
      calls.push(["show", preserveFocus]);
    },
  };
  const { vscode } = fixture([existing]);
  vscode.window.createTerminal = () => {
    throw new Error("activation created a duplicate agent terminal");
  };
  assert.strictEqual(extension.activate({}, vscode, enabledMarker, () => { throw new Error("claimed"); }), existing);
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
  assert.strictEqual(extension.activate({}, vscode, enabledMarker, () => "claim"), created[0]);
}

{
  const busy = new Error("already attached");
  busy.status = 3;
  const { vscode, calls } = fixture();
  assert.strictEqual(extension.activate({}, vscode, enabledMarker, () => { throw busy; }), undefined);
  assert.deepStrictEqual(calls, []);
}

// Two extension hosts have independent terminal collections. The helper's
// process-wide claim allows exactly one of them to create a terminal.
{
  const sharedState = path.join(directory, "two-host-state");
  const bin = path.join(directory, "bin");
  fs.mkdirSync(bin);
  fs.symlinkSync(
    path.join(__dirname, "..", "core", "nvt-session-attach.sh"),
    path.join(bin, "nvt-session-attach"),
  );
  const previousPath = process.env.PATH;
  const previousState = process.env.NVT_STATE_DIR;
  process.env.PATH = `${bin}:${previousPath}`;
  process.env.NVT_STATE_DIR = sharedState;
  try {
    const first = fixture();
    const second = fixture();
    assert.strictEqual(extension.activate({}, first.vscode, enabledMarker), first.created[0]);
    assert.strictEqual(extension.activate({}, second.vscode, enabledMarker), undefined);
    assert.strictEqual(first.created.length + second.created.length, 1);
  } finally {
    process.env.PATH = previousPath;
    if (previousState === undefined) delete process.env.NVT_STATE_DIR;
    else process.env.NVT_STATE_DIR = previousState;
  }
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
