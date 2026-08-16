require("dotenv").config();
const express = require("express");
const { execFile } = require("child_process");
const util = require("util");
const execFileAsync = util.promisify(execFile);

/**
 * Runs directly on each edge VPS (the box actually running `wg-quick up
 * wg0`). The main backend calls this agent to add/remove a peer when a
 * user starts/stops a boost session, and to read live transfer stats for
 * that peer. This is what makes tunnelService.js's registerPeerOnEdgeNode
 * real instead of a stub — deploy this file next to the node's WireGuard
 * install and point the main backend's server registry at it.
 *
 * Security: every request must include the shared secret in
 * `X-Agent-Secret`. Put this agent behind the node's firewall so only the
 * main backend's IP can reach it — do not expose port 7999 publicly.
 */

const WG_INTERFACE = process.env.WG_INTERFACE || "wg0";
const EGRESS_IFACE = "enp3s0";
//process.env.EGRESS_IFACE || 
// docs/DEPLOYMENT.md documents adding PostUp/PostDown NAT rules to
// wg0.conf by hand — a real, easy-to-skip step. Without it, a peer's
// handshake still succeeds (so the app shows "Connected") but the VPS
// never forwards its packets anywhere, which is exactly "connected but
// nothing works" for a whole-device (no game selected) tunnel. Doing it
// here on agent startup means a node works correctly the moment
// edge-agent is running, with or without the manual wg0.conf edit.
async function ensureNat() {
  try {
    await execFileAsync("sysctl", ["-w", "net.ipv4.ip_forward=1"]);
  } catch (e) {
    console.warn(`[edge-agent] couldn't set ip_forward (needs root?): ${e.message}`);
  }

  try {
    // -C checks whether the rule already exists without adding a duplicate.
    await execFileAsync("iptables", ["-t", "nat", "-C", "POSTROUTING", "-o", EGRESS_IFACE, "-j", "MASQUERADE"]);
    console.log(`[edge-agent] MASQUERADE rule for ${EGRESS_IFACE} already present`);
  } catch {
    try {
      await execFileAsync("iptables", ["-t", "nat", "-A", "POSTROUTING", "-o", EGRESS_IFACE, "-j", "MASQUERADE"]);
      console.log(`[edge-agent] added MASQUERADE rule for ${EGRESS_IFACE}`);
    } catch (e) {
      console.error(
        `[edge-agent] FAILED to add MASQUERADE rule — this node will accept handshakes but pass no real ` +
          `traffic for full-device tunnels until this is fixed: ${e.message}`
      );
    }
  }
}

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers["x-agent-secret"] !== process.env.AGENT_SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
});

app.get("/health", (req, res) => res.json({ ok: true, interface: WG_INTERFACE }));

// Adds a WireGuard peer to the running interface for a new boost session.
app.post("/peers", async (req, res) => {
  const { publicKey, allowedIp } = req.body;
  if (!publicKey || !allowedIp) return res.status(400).json({ error: "publicKey and allowedIp are required" });

  try {
    await execFileAsync("wg", ["set", WG_INTERFACE, "peer", publicKey, "allowed-ips", allowedIp]);
    // Persist so the peer survives this node's own reboots (wg-quick reads
    // the config file, not just the in-memory interface state).
    await execFileAsync("wg-quick", ["save", WG_INTERFACE]).catch(() => {
      // wg-quick save isn't available on every distro's wireguard-tools
      // build — if it fails, the peer still works until next reboot; add
      // the same `wg set` line to /etc/wireguard/wg0.conf manually or via
      // your own config-management step if you need it to persist.
    });
    res.status(201).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Removes a peer when a boost session ends (disconnect, subscription
// lapse, etc.) — keeps the node's peer list from growing unbounded.
app.delete("/peers/:publicKey", async (req, res) => {
  try {
    await execFileAsync("wg", ["set", WG_INTERFACE, "peer", req.params.publicKey, "remove"]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Live per-peer transfer stats, for the app's data-usage screen and for
// this node's own load reporting back to the main backend.
app.get("/stats", async (req, res) => {
  try {
    const { stdout } = await execFileAsync("wg", ["show", WG_INTERFACE, "dump"]);
    const lines = stdout.trim().split("\n").slice(1); // first line is the interface itself
    const peers = lines
      .filter(Boolean)
      .map((line) => {
        const [publicKey, , , allowedIps, latestHandshake, rxBytes, txBytes] = line.split("\t");
        return { publicKey, allowedIps, latestHandshake: Number(latestHandshake), rxBytes: Number(rxBytes), txBytes: Number(txBytes) };
      });
    res.json({ peers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 7999;
ensureNat().finally(() => {
  app.listen(PORT, () => console.log(`Edge agent for ${WG_INTERFACE} listening on :${PORT}`));
});
