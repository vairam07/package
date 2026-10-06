# n8n-nodes-microsoft-sso-form

Form trigger for n8n protected by Microsoft Entra ID sign-in (OIDC auth code + PKCE), with optional email-domain and **group** restriction. Supports all Form Trigger field types: text, number, email, password, textarea, date, dropdown, radio, checkbox, file, hidden, custom HTML.

## Entra setup
1. App registrations → New → single tenant. Platform **Web**, redirect URIs = the node's Test and Production form URLs (the same URL the form is served on).
2. Certificates & secrets → new client secret.
3. API permissions: Microsoft Graph delegated `openid`, `profile`, `email`, `User.Read`; grant admin consent.
4. For group restriction: Token configuration → Add groups claim (Security groups), or leave it off — the node falls back to Graph `checkMemberGroups`.
5. Optional: Enterprise app → "Assignment required" for a second layer of enforcement.

## n8n setup
Create a **Microsoft SSO Form API** credential (tenant GUID, client ID/secret, 32+ char session secret). Set `WEBHOOK_URL` to your public HTTPS URL. Add the node, configure fields and Access Control (domain / group object IDs).

Password reset: with **Enable Password Reset** on, the signed-in page shows the user's email, a "Reset password" link (new + confirm password), and Sign out. Saving outputs `{ action: 'passwordReset', newPassword, submittedAt, user }` to the next node. The password is plain text in the execution data, so apply it immediately (e.g. Graph `PATCH /users/{id}` with `passwordProfile`) and consider disabling "Save successful executions" for that workflow.

Output: submitted fields plus `submittedAt` and `user` `{oid,name,email,tenantId,groups}`.

## Install
`npm install && npm run build`, then `npm pack` and install the tarball via Settings → Community Nodes, or copy into `~/.n8n/custom`.
