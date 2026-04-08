// T1552.008 — Chat Messages — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.008",
    name: "Chat Messages",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "CHAT SOURCE",  x: 80 },
      { label: "SEARCH",       x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "slack_teams", label: "Slack / Teams", sub: "Enterprise chat", x: 80, y: 130, r: 36, type: "source",
      tags: ["Slack", "Microsoft Teams", "Discord", "Enterprise chat"],
      telemetry: [],
      api: "Slack Workspace, Microsoft Teams, Discord — enterprise and project communication",
      artifact: "Chat platform containing shared credentials, API keys, configuration details",
      desc: "Enterprise chat platforms (Slack, Teams, Discord) are frequently used to share credentials among team members: 'here's the password for the staging DB', API keys, SSH passphrases, WiFi passwords, and service account credentials. Search functionality makes finding these trivial.",
      src: "MITRE ATT&CK T1552.008" },

    { id: "direct_msg", label: "Direct Messages", sub: "Private chats", x: 80, y: 330, r: 34, type: "source",
      tags: ["DMs", "Private messages", "1:1 chats", "Webhook URLs"],
      telemetry: [],
      api: "Direct messages between users — often used to share sensitive information privately",
      artifact: "DMs containing passwords, tokens, or sensitive configuration",
      desc: "Direct messages between users often contain credentials shared 'privately': temporary passwords, one-time setup credentials, webhook URLs (which are effectively API tokens), service accounts created for specific projects, and links to sensitive resources with credentials.",
      src: "MITRE T1552.008" },

    { id: "chat_search", label: "Search Messages", sub: "API or UI", x: 270, y: 200, r: 40, type: "source",
      tags: ["Slack API search", "Teams Graph API", "Search 'password'"],
      telemetry: [],
      api: "Slack: /api/search.messages?query=password · Teams: Graph API /messages search · UI search",
      artifact: "Chat API calls searching for credential-related keywords",
      desc: "Attacker searches chat history for credentials: Slack API (search.messages with terms like 'password', 'API key', 'credentials'), Microsoft Graph API for Teams messages, or simply using the chat platform's built-in search. With compromised user credentials or OAuth token, the attacker can search all channels the user has access to.",
      src: "MITRE T1552.008" },

    { id: "ev_detect", label: "Chat API Audit", sub: "Search monitoring", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Slack audit log", "Teams audit log", "API search patterns", "Unusual search volume"],
      telemetry: [],
      api: "Chat platform audit logs: keyword searches for credentials + unusual access patterns",
      artifact: "OPTIMAL: Slack audit log: search.messages calls · Teams audit: message search · bulk channel access · credential keyword searches",
      desc: "OPTIMAL DETECTION NODE. (1) Slack Enterprise: audit logs show search.messages API calls with query terms. (2) Microsoft Teams: Compliance Center audit logs for message search and access. (3) Pattern: large volume of channel history reads or searches for credential-related keywords. (4) OAuth token: monitor for new app integrations with message.read scope. (5) PREVENTION: DLP policies preventing password sharing in chat, credential hygiene training, Slack Enterprise Grid DLP.",
      src: "MITRE T1552.008; Slack Enterprise audit; Microsoft 365 compliance" },

    { id: "shared_creds", label: "Shared Creds", sub: "From messages", x: 730, y: 200, r: 38, type: "source",
      tags: ["Database passwords", "API tokens", "SSH creds", "Webhook URLs"],
      telemetry: [],
      api: "Credentials shared via chat: DB passwords, API tokens, SSH credentials, webhook URLs",
      artifact: "Plaintext credentials harvested from chat message history",
      desc: "Credentials found in chat: database passwords, API keys and tokens, SSH passwords/keys, AWS access keys, webhook URLs, VPN credentials, WiFi passwords, admin panel credentials, and one-time passwords that never expired. Users often forget that messages persist and are searchable.",
      src: "MITRE T1552.008" },
  ],

  edges: [
    { f: "slack_teams", t: "chat_search" },
    { f: "direct_msg", t: "chat_search" },
    { f: "chat_search", t: "ev_detect" },
    { f: "ev_detect", t: "shared_creds" },
  ],
};

export default model;
