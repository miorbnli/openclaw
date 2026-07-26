import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const candidateDir = process.env.PROOF_CANDIDATE_DIR;
const candidateSha = process.env.PROOF_CANDIDATE_SHA;
const stateDir = process.env.PROOF_STATE_DIR;
const workflowSha = process.env.PROOF_WORKFLOW_SHA;

if (!candidateDir || !candidateSha || !stateDir || !workflowSha) {
  throw new Error("missing proof environment");
}

const fixture = {
  triggers: ["sqlite wake"],
  routing: {
    defaultTarget: { mode: "current" },
    routes: [{ trigger: "sqlite route", target: { agentId: "sqlite-agent" } }],
  },
  legacyTriggers: { triggers: ["legacy wake"] },
  legacyRouting: {
    defaultTarget: { agentId: "legacy-agent" },
    routes: [{ trigger: "legacy route", target: { agentId: "legacy-route-agent" } }],
  },
};

const result = {
  candidateSha,
  harnessSha256: createHash("sha256")
    .update(await fs.readFile(new URL(import.meta.url)))
    .digest("hex"),
  workflowSha,
  assertions: {
    canonicalSqlitePreserved: false,
    firstReady: false,
    legacySourcesRetired: false,
    ownedGatewayStopped: false,
    receiptsPrivate0600: false,
    secondReady: false,
  },
};

let child;

const runCandidate = (args, env) => {
  const completed = spawnSync(process.execPath, args, {
    cwd: candidateDir,
    encoding: "utf8",
    env,
    gid: 1000,
    timeout: 30_000,
    uid: 1000,
  });
  if (completed.status !== 0) {
    throw new Error("candidate seed command failed");
  }
};

const allocateLoopbackPort = async () => {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  if (!address || typeof address === "string") {
    throw new Error("failed to allocate loopback port");
  }
  return address.port;
};

const isReady = (url) =>
  new Promise((resolve) => {
    const request = http.get(url, { timeout: 1_000 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.once("end", () => {
        try {
          const readiness = JSON.parse(body);
          resolve(
            response.statusCode === 200 &&
              readiness.ready === true &&
              readiness.failing?.length === 0,
          );
        } catch {
          resolve(false);
        }
      });
    });
    request.once("timeout", () => {
      request.destroy();
      resolve(false);
    });
    request.once("error", () => resolve(false));
  });

const stopGateway = async () => {
  if (!child?.pid) {
    return false;
  }
  const current = child;
  const exited = new Promise((resolve) => current.once("exit", (code) => resolve(code === 0)));
  try {
    process.kill(-current.pid, "SIGTERM");
  } catch {
    return false;
  }
  const clean = await Promise.race([
    exited,
    new Promise((resolve) => setTimeout(() => resolve(false), 3_000)),
  ]);
  if (clean) {
    child = undefined;
    return true;
  }
  try {
    process.kill(-current.pid, "SIGKILL");
  } catch {
    return false;
  }
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3_000))]);
  child = undefined;
  return false;
};

const startGateway = async (configPath) => {
  const gatewayPort = await allocateLoopbackPort();
  let spawnError;
  child = spawn(
    process.execPath,
    [
      "dist/index.js",
      "gateway",
      "run",
      "--allow-unconfigured",
      "--auth",
      "none",
      "--bind",
      "loopback",
      "--port",
      String(gatewayPort),
    ],
    {
      cwd: candidateDir,
      detached: true,
      env: {
        HOME: path.join(stateDir, "home"),
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        NO_COLOR: "1",
        OPENCLAW_CONFIG_PATH: configPath,
        OPENCLAW_GATEWAY_PASSWORD: "",
        OPENCLAW_GATEWAY_TOKEN: "",
        OPENCLAW_HOME: path.join(stateDir, "home"),
        OPENCLAW_SKIP_BROWSER_CONTROL_SERVER: "1",
        OPENCLAW_SKIP_CANVAS_HOST: "1",
        OPENCLAW_SKIP_CHANNELS: "1",
        OPENCLAW_SKIP_CRON: "1",
        OPENCLAW_SKIP_GMAIL_WATCHER: "1",
        OPENCLAW_SKIP_PROVIDERS: "1",
        OPENCLAW_STATE_DIR: stateDir,
        PATH: "/usr/local/bin:/usr/bin:/bin",
        USERPROFILE: path.join(stateDir, "home"),
      },
      gid: 1000,
      stdio: "ignore",
      uid: 1000,
    },
  );
  child.once("error", (error) => {
    spawnError = error;
  });
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (spawnError || child.exitCode !== null) {
      return false;
    }
    if (await isReady(`http://127.0.0.1:${gatewayPort}/readyz`)) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return false;
};

const verifyState = async (settingsDir) => {
  const database = new DatabaseSync(path.join(stateDir, "state", "openclaw.sqlite"), {
    readOnly: true,
  });
  try {
    const triggers = database
      .prepare("SELECT trigger FROM voicewake_triggers WHERE config_key = ? ORDER BY position")
      .all("default")
      .map((row) => row.trigger);
    const defaultTarget = database
      .prepare(
        "SELECT default_target_mode, default_target_agent_id, default_target_session_key FROM voicewake_routing_config WHERE config_key = ?",
      )
      .get("default");
    const routes = database
      .prepare(
        "SELECT trigger, target_mode, target_agent_id, target_session_key FROM voicewake_routing_routes WHERE config_key = ? ORDER BY position",
      )
      .all("default");
    result.assertions.canonicalSqlitePreserved =
      JSON.stringify(triggers) === JSON.stringify(fixture.triggers) &&
      JSON.stringify(defaultTarget) ===
        JSON.stringify({
          default_target_mode: "current",
          default_target_agent_id: null,
          default_target_session_key: null,
        }) &&
      JSON.stringify(routes) ===
        JSON.stringify([
          {
            trigger: "sqlite route",
            target_mode: "agent",
            target_agent_id: "sqlite-agent",
            target_session_key: null,
          },
        ]);
  } finally {
    database.close();
  }

  result.assertions.legacySourcesRetired = await Promise.all(
    ["voicewake.json", "voicewake-routing.json"].map(async (name) => {
      try {
        await fs.access(path.join(settingsDir, name));
        return false;
      } catch {
        return true;
      }
    }),
  ).then((values) => values.every(Boolean));
  result.assertions.receiptsPrivate0600 = await Promise.all(
    [
      ["voicewake.json.migrated", "legacy wake"],
      ["voicewake-routing.json.migrated", "legacy route"],
    ].map(async ([name, expectedFixture]) => {
      const receiptPath = path.join(settingsDir, name);
      return (
        ((await fs.stat(receiptPath)).mode & 0o777) === 0o600 &&
        (await fs.readFile(receiptPath, "utf8")).includes(expectedFixture)
      );
    }),
  ).then((values) => values.every(Boolean));
};

try {
  const configPath = path.join(stateDir, "home", ".openclaw", "openclaw.json");
  const settingsDir = path.join(stateDir, "home", ".openclaw", "settings");
  await fs.mkdir(settingsDir, { recursive: true });
  await Promise.all([
    fs.chown(stateDir, 1000, 1000),
    fs.chown(path.join(stateDir, "home"), 1000, 1000),
    fs.chown(path.join(stateDir, "home", ".openclaw"), 1000, 1000),
    fs.chown(settingsDir, 1000, 1000),
  ]);
  await fs.writeFile(
    configPath,
    `${JSON.stringify({
      gateway: {
        auth: { mode: "none" },
        bind: "loopback",
        controlUi: { enabled: false },
        mode: "local",
        tailscale: { mode: "off" },
      },
      plugins: { enabled: false },
    })}\n`,
  );
  const seed = `
import { setVoiceWakeTriggers } from "./src/infra/voicewake.js";
import { setVoiceWakeRoutingConfig } from "./src/infra/voicewake-routing.js";
await setVoiceWakeTriggers(${JSON.stringify(fixture.triggers)}, process.env.OPENCLAW_STATE_DIR);
await setVoiceWakeRoutingConfig(${JSON.stringify(fixture.routing)}, process.env.OPENCLAW_STATE_DIR);
`;
  runCandidate(["--input-type=module", "--import", "tsx", "--eval", seed], {
    HOME: path.join(stateDir, "home"),
    OPENCLAW_STATE_DIR: stateDir,
    PATH: "/usr/local/bin:/usr/bin:/bin",
  });
  await fs.writeFile(
    path.join(settingsDir, "voicewake.json"),
    `${JSON.stringify(fixture.legacyTriggers)}\n`,
  );
  await fs.writeFile(
    path.join(settingsDir, "voicewake-routing.json"),
    `${JSON.stringify(fixture.legacyRouting)}\n`,
  );

  result.assertions.firstReady = await startGateway(configPath);
  result.assertions.ownedGatewayStopped = await stopGateway();
  await verifyState(settingsDir);
  result.assertions.secondReady = await startGateway(configPath);
  result.assertions.ownedGatewayStopped &&= await stopGateway();
  await verifyState(settingsDir);
} catch {
  // The fixed result schema intentionally excludes candidate-controlled diagnostics.
} finally {
  await stopGateway().catch(() => undefined);
}

process.stdout.write(`${JSON.stringify(result)}\n`);
