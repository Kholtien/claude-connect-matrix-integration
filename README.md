# claude-matrix-e2ee

A Matrix channel plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that wires an end-to-end encrypted Matrix room into a running Claude Code session. Send a message from any Matrix client (Element, FluffyChat, Cinny), Claude sees it, Claude replies back into the encrypted room.

Works wherever Claude Code runs: headless servers, WSL, SSH sessions, plain terminals. No desktop app, no third party messaging service sitting in the middle.

This is a fork of [metalchef1/Claude-Connect-Matrix-Integration](https://github.com/metalchef1/Claude-Connect-Matrix-Integration) with the Matrix I/O layer rewritten on top of [`matrix-bot-sdk`](https://github.com/turt2live/matrix-bot-sdk) so the bot can actually join encrypted rooms. The crypto self-signing routine is lifted from [Kholtien/nanoclaw](https://github.com/Kholtien/nanoclaw).

---

## What's different from upstream

| | Upstream metalchef1 | This fork |
|---|---|---|
| Runtime | Bun | Node 20+ via `tsx` |
| Matrix layer | Raw `fetch` to CS API | `matrix-bot-sdk` + `RustSdkCryptoStorageProvider` |
| Encrypted rooms | ❌ plaintext only | ✅ Olm/Megolm via the Rust crypto SDK |
| Device verification | n/a | Auto self-signs the bot's device using its SSSS recovery key on every restart |
| Identity persistence | n/a | Pinned device-ID re-login keeps the bot's crypto identity stable across restarts |
| MCP protocol / tools / allowlist / permission relay | (kept verbatim) | (kept verbatim) |

---

## Requirements

| Requirement | Notes |
|---|---|
| **Self-hosted Matrix homeserver** | Conduit, Tuwunel, Synapse, Dendrite, anything you run yourself. The bot's credentials have to be readable on the machine running Claude Code. |
| **Node.js ≥ 20** | The Rust crypto binding is a native Node module. Bun might work, I haven't tried. |
| **Claude Code 2.x** | With Channels support |
| **A bot Matrix account** | Registered on your homeserver |
| **Secure Backup enabled on the bot account** | Optional but recommended. Without it the bot still works, but Element will keep flagging its device as unverified. |

---

## Setup

### 1. Clone

```bash
git clone https://github.com/Kholtien/claude-connect-matrix-integration ~/projects/claude-matrix-e2ee
cd ~/projects/claude-matrix-e2ee
git checkout e2ee-port
npm install
```

### 2. Create the bot account

Register a fresh user on your homeserver. Any Matrix client will do, or curl if you prefer. Pick a strong password, you'll need it in a moment.

```bash
curl -X POST https://your.homeserver/_matrix/client/v3/register \
  -H "Content-Type: application/json" \
  -d '{"username":"claude-bot","password":"<strong>","kind":"user"}'
```

### 3. Set up Secure Backup on the bot (optional but recommended)

Log into Element as the bot account and go to **Settings → Security & Privacy → Secure Backup → Set up**. Save the recovery key somewhere, it's what you'll feed into `MATRIX_RECOVERY_KEY`. Skip this and the bot will still run, it'll just look perpetually unverified to other devices in the room.

### 4. Create the room

From your *personal* account, create a private encrypted room and invite the bot. The bot auto-accepts the invite only if the room matches `MATRIX_ROOM_ID`, everything else is ignored. Grab the internal room ID from your client (in Element: Room Settings → Advanced → Internal room ID).

### 5. Configure credentials

Create `~/.claude/channels/matrix-e2ee/.env` (mode `0600`):

```bash
MATRIX_HOMESERVER_URL=https://your.homeserver
MATRIX_USER_ID=@claude-bot:your.homeserver
MATRIX_ROOM_ID=!yourroomid:your.homeserver
MATRIX_PASSWORD=<bot password>
MATRIX_RECOVERY_KEY=<bot SSSS recovery key, optional>
MATRIX_E2EE=true
```

You can use `MATRIX_ACCESS_TOKEN` instead of `MATRIX_PASSWORD`, but password is preferred. With a password the plugin can pin the bot's crypto device ID across restarts, which keeps Olm state intact, so you don't end up with a fresh "unverified" device every time the service bounces.

Or just run `/matrix:configure`, which is the path I'd recommend. It asks for each value, writes the file with the right permissions, and won't overwrite anything you didn't ask it to change.

### 6. Register with Claude Code

```bash
claude mcp add matrix -s user -- npx -y tsx ~/projects/claude-matrix-e2ee/server.ts
```

No `-e` flags — secrets stay in the `.env` file out of `~/.claude.json`.

### 7. Add yourself to the allowlist

```bash
claude --dangerously-load-development-channels server:matrix
# in the session:
/matrix:access allow @you:your.homeserver
```

Anything from a user who isn't on the allowlist is silently dropped. Invites to rooms other than the configured `ROOM_ID` are ignored.

### 8. Launch

```bash
claude --dangerously-load-development-channels server:matrix
```

The `--dangerously-load-development-channels` flag is required because this plugin isn't on Anthropic's official channel allowlist. It opts the session into inbound message delivery from unlisted MCP servers. Scary-sounding flag, fairly mundane reason.

If you're running this a lot, alias it:

```bash
alias claude='claude --dangerously-load-development-channels server:matrix'
```

---

## Optional: run as a background service

If you want an always-on bot you can message from anywhere, `/matrix:configure systemd` will scaffold a systemd user unit and a tmux wrapper. The wrapper runs Claude Code inside `tmux -L claude-matrix` so you can attach locally (`tmux -L claude-matrix attach -t matrix-<workdir-name>`) to see what the bot is actually doing.

The systemd path needs:
- A working systemd user session. On most distros that means `loginctl enable-linger $USER` so it survives logout.
- `tmux` installed.

If systemd isn't your thing, any supervisor works: s6, runit, supervisord, screen, whatever. The plugin itself is just a stdio MCP server. Claude Code is the actual long-running process you need to keep alive.

---

## Skills

| Skill | What it does |
|---|---|
| `/matrix:configure` | Full setup walkthrough: prereqs, repo, npm install, homeserver config, bot creation, room ID, SSSS key, MCP registration, allowlist, optional systemd+tmux. Safe to re-run to update a single value. |
| `/matrix:access` | Manage the inbound allowlist: `allow @user`, `remove @user`, `list`, `policy disabled` |

The `/matrix:access` skill will refuse to process access-list changes that come in over Matrix. That's a prompt-injection vector and it has to stay closed. Only commands typed directly into the terminal are honoured.

---

## Approving tool permissions from Matrix

When Claude wants to run a tool (Bash, Write, Edit, etc.), it sends a permission request to the room:

```
🔐 Permission: Bash
Run a shell command.

`{"command":"ls -la"}`

React 👍 to allow or 👎 to deny. (Or reply yes abcde / no abcde)
```

React with 👍 or ✅ to allow, 👎 or ❌ to deny. If your client doesn't support reactions, reply with `yes abcde` / `no abcde` using the ID in the message.

---

## !commands

The plugin intercepts messages starting with `!` before they reach Claude — zero tokens, instant response.

| Command | What it does |
|---|---|
| `!help` | List all commands |
| `!status` | Service state and uptime |
| `!context` | Context window usage for the current session |
| `!context all` | Usage across all sessions |
| `!clear` | Clear Claude's context and start fresh |
| `!compact` | Compact the context (summarise and continue) |
| `!model <name>` | Switch model — aliases: `opus`, `sonnet`, `haiku`, or a full model ID |
| `!restart` | Restart the bridge service |

---

## Multiple-choice questions

Claude Code's interactive question UI is terminal-only and can't reach Matrix. Instead, Claude formats choices as a numbered list and you react with the corresponding number:

```
❓ Which approach would you prefer?

1️⃣  Keep it simple, ship now
2️⃣  Add tests first
3️⃣  Refactor the whole thing
```

React with 1️⃣, 2️⃣, etc. to select. The bot reacts back with ✓ to confirm it registered, then continues. You can also just type the number as a message if reactions feel awkward.

---

## Security notes

### Threat model

This plugin assumes you're pointing it at a homeserver you control. The bot's password and SSSS recovery key live in a local `.env` file, and anyone with read access to `~/.claude/channels/matrix-e2ee/` effectively owns the bot's identity. Defence is filesystem permissions: `0700` on the directory, `0600` on the files. If that isn't enough for your setup, this probably isn't the right tool.

### Allowlist + permission relay

- Inbound Matrix messages are dropped unless the sender is on the allowlist (`access.json`).
- Permission grant reactions are only honoured for requests the plugin actually relayed. Forging a grant ID preemptively gets rejected with a ❓ reaction.
- Auto-join is restricted to the configured `MATRIX_ROOM_ID`. Invites to any other room are ignored.

### Known dependency advisories

`matrix-bot-sdk@0.8.0` transitively pulls in the deprecated `request` package, which drags along advisories on `form-data`, `tough-cookie`, and `qs`. `npm audit` currently reports 2 critical and 5 moderate vulnerabilities.

These are reachable. Every Matrix HTTP request goes through the affected stack. Risk-accepted here because:
- The bot only talks to a homeserver you run yourself, on a known URL (`MATRIX_HOMESERVER_URL`). The attack surface is a server you already trust.
- There's no upstream fix in `matrix-bot-sdk@0.8.x`. The SDK author has said `request` will be removed in a future major.
- The specific advisories don't apply to how this plugin uses the stack: `form-data`'s unsafe-random boundary issue is irrelevant when sending JSON (no multipart bodies), `tough-cookie`'s prototype pollution needs attacker-controlled cookies that a Matrix homeserver never sets, and `qs` DoS needs attacker-controlled query strings that the Matrix CS API doesn't use.

If you'd rather not take that on, run the bot in a container with outbound network locked down to your homeserver, or wait for a `matrix-bot-sdk` release that drops `request` entirely.

### Stdio MCP hygiene

`matrix-bot-sdk` writes its internal logs to stdout by default, which corrupts the JSON-RPC channel stdio MCP servers communicate on. The plugin overrides `LogService` at boot to redirect everything to stderr. Don't remove that override, the server will start spraying log lines into the RPC stream and Claude Code will start seeing garbage.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `MATRIX_HOMESERVER_URL` | ✓ | Base URL of your homeserver, e.g. `https://chat.example.com` |
| `MATRIX_USER_ID` | ✓ | Bot's full Matrix ID, e.g. `@claude-bot:chat.example.com` |
| `MATRIX_ROOM_ID` | ✓ | Internal ID of the encrypted room, e.g. `!abc123:chat.example.com` |
| `MATRIX_PASSWORD` | one of pwd/token | Bot password. Preferred, since it enables device-ID pinning. |
| `MATRIX_ACCESS_TOKEN` | one of pwd/token | Existing access token, if you don't want to store a password. |
| `MATRIX_RECOVERY_KEY` | optional | Bot's SSSS recovery key, for automatic device verification. |
| `MATRIX_E2EE` | optional | `true` (default) or `false`. Set `false` to disable Olm if you're only using plaintext rooms. |
| `MATRIX_STATE_DIR` | optional | Override the state directory (default `~/.claude/channels/matrix-e2ee`). |
| `MATRIX_ACCESS_MODE` | optional | `static` reads `access.json` once at startup instead of on every message. |

---

## Credits

- **[metalchef1/Claude-Connect-Matrix-Integration](https://github.com/metalchef1/Claude-Connect-Matrix-Integration)** — original MCP plugin, allowlist design, permission-relay protocol, all the Claude Code integration plumbing this fork keeps verbatim.
- **[Kholtien/nanoclaw](https://github.com/Kholtien/nanoclaw)** — pinned-device re-login + SSSS auto-sign routines, ported to a standalone `crypto.ts` here.
- **[matrix-bot-sdk](https://github.com/turt2live/matrix-bot-sdk)** — the SDK that does the actual Matrix client work.

## License

Apache 2.0 (inherited from upstream)
