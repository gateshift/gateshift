# The MCP endpoint

Gateshift offers an MCP server (Model Context Protocol) as part of the
installation: an AI client of your choice, any client that speaks MCP, reads
and operates a Gateshift installation through the automation
API (docs/API.md). The endpoint is `/mcp` on the same address, port and
certificate as the pages. Nothing is installed beside the client.

Gateshift hosts no model and sends nothing to a model provider itself. The
client you plug in does: every tool result the server returns goes to that
client's model provider, and clients keep transcripts on disk. The rules,
objects and names an agent reads leave the installation that way, by your
choice of client.

## What it offers

Forty-seven tools and one resource template that serves three documents,
each a call of the API with the connection's token.

- **Reads.** Tenants, Devices (never their credentials), projects with the
  step model's progress and the build state, interfaces, zones, virtual
  routers, rules in pages and rules by hash with every effective field, the
  objects of a kind with the lint flags (unused, duplicate name or value),
  the project's name map, the target's stored catalogues (applications,
  profiles, logging, UTM, threat layers) and the zone picker's, the last
  build's findings with the sentence that explains each kind and the tool
  that resolves it, exclusions, push settings, VPN tunnels (whether a key is
  stored, never the key), jobs with their events, and the audit of what was
  changed through the API and why. Also the routes, the NAT rules
  (by hash, with the project's overrides marked), the snapshots of the
  project's decisions, and the fields of a kind (`describe_kind`: what
  `add_item`, `edit_item` and `delete_item` accept, with the target's
  property keys).
- **Changes an agent may make on its own word, with a reason.** Rename an
  interface, bind it to a zone or skip it, make it a VLAN on one of the target's
  ports (type, parent, tag) or give it its addresses. Disable, enable, exclude or restore
  rules (at most fifty a call), set push settings, create a zone, reset or
  derive the rules' zones from the routes, leave a virtual router out. Also
  the curation of the Objects tab and the enrichment panes: rename
  objects, services, interfaces, zones, virtual routers, NAT rules and rules
  by a scheme or an explicit map (the naming workbench: the plan is a set, a
  collision refuses the whole batch, the inverse map undoes it), leave
  objects out with the partition of what a rule still needs, merge
  duplicates, set one field of up to fifty rules (zones, service,
  applications from the target's catalogue, profiles, logging, track,
  schedule, negate), refused for a field the target's renderer does not read,
  place a rule before or after another and reset the order, read a catalogue
  from the target Device, and assign the target's applications by port or
  by name as a job. And the network strand and the NAT rules by kind: add an
  interface (with its zone and connected routes), a route, a virtual router
  or a NAT rule as the project's own row, edit a route, a zone's colour,
  external flag or properties, or a NAT rule's name, description, state,
  properties, zone overlay and negates, delete any of them in the project (an
  imported row becomes an exclusion the Dashboard restores, the project's own
  row is removed, a zone that rules still use moves them to its members
  first, after an auto-snapshot), and take a snapshot of the project's
  decisions as a safety net (no confirmation: it changes no decision). Each
  tool first returns what it would change and writes only when called again
  with `confirm`. Every write lands in the audit
  under the token's name with the agent's reason, and the page can undo it.
  Refreshing the ruleset and building the target configuration run without
  a confirmation: nothing leaves Gateshift. Fetching the target's inventory
  runs without one too: Gateshift opens a session to the target Device and
  reads its interfaces, zones, virtual routers, routes and catalogues,
  nothing is written to the Device. Reading one catalogue from the target
  (`refresh_catalog`) asks for `confirm` like a change.
- **Changes that need you.** Marking a build's findings as reviewed, and
  restoring the project's decisions from a snapshot (every decision made
  since is discarded, after an auto-snapshot of the state before). The
  server shows you a message in the client (the build's age and summary, the
  snapshot, and what the agent changed since the last confirmed action) and
  asks you to choose. The agent cannot answer that question. A client that
  cannot show the question, or a non-interactive run, gets a refusal.
- **What no tool does: push.** Pushing a strand to the target, publishing or
  discarding what a push staged on a Check Point management are the
  operator's, on the Review & Deploy page. The agent curates, builds, reads
  the findings and says that the build is ready. A message in a chat is not
  the review page, a client may answer a question by itself, and the text of
  a configuration is the model's context: so no tool writes to a Device.
- **The documents.** `gateshift://docs/operating`, `gateshift://docs/api` and
  `gateshift://docs/known-limitations`: the operating guide, the API document
  and the known limitations of the installation, in its version, so the
  model's answers about what Gateshift does and does not do are the product's
  own words.

What the server never does: push, publish or discard, register, edit or delete a Device, import or
collect, create or delete a project, read or set a key or a certificate, list
tokens. Those stay with you on the page.

## Setting it up

1. Create a token on the Automation page (`/automation`, under Manage in the
   navigation) with the scope `project`, named after the agent or the program
   that uses it. The scope cannot push and cannot touch Devices, keys,
   projects' life cycle or tokens, even if the token leaves your hands.
   `/mcp` takes any live token: with `read` the writes are refused, with
   `full` the tools stay the same but the token in the client's
   configuration can push through the API. Give an agent `project`. An
   expiry is a good habit. The page names the endpoint.
2. Give the client three things: the transport Streamable HTTP, the URL
   of the endpoint and the token in the `Authorization` header. Many clients
   read them from a configuration file of this form (the exact keys are the
   client's, see its documentation):

   ```
   {
     "mcpServers": {
       "gateshift": {
         "url": "https://gateshift.example.net/mcp",
         "headers": { "Authorization": "Bearer gs_..." }
       }
     }
   }
   ```

   Most clients connect from the machine they run on. Some connect from
   their provider's cloud instead: for those the installation must be
   reachable from the internet on port 443 with a publicly trusted
   certificate, and a LAN address or a self-signed certificate does not
   work. The client's documentation says which way it connects.

The token lands in the client's configuration in plain text. Keep it in the
client's user or local scope, never in a project file that lives in a
repository, and revoke it on the Automation page when the agent goes.

For a client that connects from your machine, a private or self-signed
certificate is the client's matter, as it is for a browser. Some clients do
not read the system's trust store and refuse the connection until they are
given the certificate (`certs/gateshift.crt` or your CA's) in the way their
documentation names.

## What to expect

- Every request carries the token. Gateshift validates it before the server
  sees the request (unknown, revoked or expired: 401, five failures from one
  address: a growing wait), and binds the client's session to it: a request
  on another token's session is refused. A session cookie never opens `/mcp`.
- Each token has its own limits. Ten calls a minute on the agent's own
  word: the confirmed changes and what runs without a confirmation (refresh,
  build, inventory fetch, snapshot) count together, a batch counts once.
  Four a minute of the kind you confirm. Four calls in flight.
- The rules, the findings, the objects, the NAT rules, the catalogues and
  the audit come in pages, fifty rows by default. The other lists come whole,
  the name map up to 500 rows. Strings are capped, and every string is
  cleared of token, header and key patterns before the model sees it. Long
  work is a job: build and refresh return a job id, and `get_job` waits
  up to a minute for it.
- A restart of Gateshift drops the clients' sessions. The client connects
  again, a confirmation that was open at that moment comes back as a
  refusal. A reverse proxy in front of Gateshift must pass server-sent
  events through unbuffered for `/mcp`.
- `GATESHIFT_MCP_READ_ONLY=1` in the installation's `.env` offers the 23
  read tools and the documents only, to every client. `1`, `true`, `yes` or
  `on` switch it on, any other value leaves it off. Docker Compose passes it
  to the web server, which reads it at start: run `docker compose up -d`
  after a change.

## Where the data goes

The endpoint answers the connection alone and sends nothing anywhere by
itself. The connection comes from the client's machine, or from its
provider's cloud for a client that connects from there. The client is an AI
host: every tool answer (rule names, descriptions,
comments, objects, zones, addresses, findings) becomes part of the model's
context and travels to the model's provider, unless the model runs on your
own hardware. Gateshift cannot prevent that, it bounds it. The server
never hands out credentials, API keys, certificates or pre-shared keys, not
even in a Device's row. The rules, objects, NAT rules, findings,
catalogues and the audit come in pages, so what flows of them is what the
model asks for, not the estate at once. The interfaces, zones, routes and
the other lists come whole. The scope `project` keeps the push, Devices,
imports, the projects' life cycle and the tokens out of reach. Every write
lands in the audit on the Automation page under the token's name, with the
agent's reason. An installation that wants none of this gives no AI client a
token (any live token opens `/mcp`), or runs the client against a model it
hosts itself.

## For developers

The package lives under `webui/gateshift_mcp/`: `api.py` (the client of the
API), `tools.py` (the tools as plain functions), `kinds.py` (the one field
table of the network kinds and the NAT rules, read by the API and the tools
alike), `state.py` (one state per token), `server.py` (the MCP wiring) and
`endpoint.py` (the endpoint in the application). The naming workbench's
pattern engine the API uses is `webui/naming.py`. `python -m gateshift_mcp`
runs the same server on stdio for development, with `GATESHIFT_URL` and
`GATESHIFT_MCP_TOKEN` in the environment.
