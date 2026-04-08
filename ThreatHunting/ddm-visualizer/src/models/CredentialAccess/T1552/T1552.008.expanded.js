// T1552.008 — Chat Messages — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.008", name: "Chat Messages", tactic: "Credential Access", platform: "Slack, Teams, Discord", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "SLACK", y: 80 }, { label: "TEAMS", y: 200 }] },
  nodes: [
    { id: "chat_access", label: "Chat Access", sub: "Token/session", x: 60, y: 130, r: 36, type: "entry", desc: "Access to chat platform via stolen token, session cookie, or compromised account.", src: "MITRE ATT&CK T1552.008" },
    { id: "slack_search", label: "Slack Search", sub: "password|secret|key", x: 220, y: 80, r: 36, type: "op", desc: "Slack message search: 'password', 'secret', 'key', 'token', 'aws_access_key_id'.", src: "MITRE T1552.008" },
    { id: "slack_api", label: "Slack API", sub: "search.messages", x: 420, y: 80, r: 34, type: "api", desc: "Slack API: search.messages with credential-related query strings. Bulk search across channels.", src: "Slack API" },
    { id: "slack_export", label: "Slack Export", sub: "Admin export", x: 420, y: 140, r: 30, type: "op", desc: "Workspace admin can export all messages for offline searching.", src: "Slack Admin" },
    { id: "teams_search", label: "Teams Search", sub: "Graph API", x: 220, y: 200, r: 34, type: "op", desc: "Microsoft Teams search via Graph API: /me/messages?$search='password'.", src: "Microsoft Graph API" },
    { id: "graph_api", label: "Graph API", sub: "/chats/messages", x: 420, y: 200, r: 34, type: "api", desc: "Microsoft Graph: GET /chats/{id}/messages — enumerate all chat messages.", src: "Microsoft Graph API" },
    { id: "sharepoint", label: "SharePoint Files", sub: "Shared in chats", x: 420, y: 260, r: 30, type: "op", desc: "Files shared in Teams stored in SharePoint — may contain credentials in documents.", src: "Microsoft Teams/SharePoint" },
    { id: "audit_log", label: "Audit Logs", sub: "Search/export events", x: 620, y: 80, r: 38, type: "detect", desc: "OPTIMAL: Slack Audit API / M365 Audit Log: message search events, bulk export triggers.", src: "Slack Audit; M365 Compliance" },
    { id: "dlp", label: "DLP Rules", sub: "Credential patterns", x: 620, y: 200, r: 34, type: "detect", desc: "DLP policies detecting credential patterns (API keys, connection strings) shared in chat.", src: "Microsoft Purview; Slack Enterprise" },
    { id: "chat_creds", label: "Shared Credentials", x: 800, y: 130, r: 38, type: "artifact", desc: "Credentials shared via chat: passwords, API keys, connection strings, infrastructure secrets.", src: "MITRE T1552.008" },
  ],
  edges: [
    { f: "chat_access", t: "slack_search" }, { f: "chat_access", t: "teams_search" },
    { f: "slack_search", t: "slack_api" }, { f: "slack_api", t: "slack_export" },
    { f: "teams_search", t: "graph_api" }, { f: "graph_api", t: "sharepoint" },
    { f: "slack_api", t: "audit_log" }, { f: "graph_api", t: "audit_log" },
    { f: "slack_api", t: "dlp" }, { f: "graph_api", t: "dlp" },
    { f: "slack_api", t: "chat_creds" }, { f: "graph_api", t: "chat_creds" }, { f: "sharepoint", t: "chat_creds" },
  ],
};
export default model;
