"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MicrosoftSsoForm = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const crypto_1 = __importDefault(require("crypto"));
const jose_1 = require("jose");
const LOGIN_COOKIE = 'msf_login';
const SESSION_COOKIE = 'msf_session';
const SCOPES = 'openid profile email User.Read';
// ---------- helpers ----------
function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
function b64url(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}
function randomString(bytes = 32) {
    return b64url(crypto_1.default.randomBytes(bytes));
}
function sign(payload, secret) {
    const body = b64url(JSON.stringify(payload));
    const mac = b64url(crypto_1.default.createHmac('sha256', secret).update(body).digest());
    return `${body}.${mac}`;
}
function verify(token, secret) {
    if (!token)
        return null;
    const [body, mac] = token.split('.');
    if (!body || !mac)
        return null;
    const expected = b64url(crypto_1.default.createHmac('sha256', secret).update(body).digest());
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto_1.default.timingSafeEqual(a, b))
        return null;
    try {
        const data = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));
        return data.exp > Date.now() ? data : null;
    }
    catch {
        return null;
    }
}
function parseCookies(header) {
    const out = {};
    for (const part of (header ?? '').split(';')) {
        const idx = part.indexOf('=');
        if (idx > 0)
            out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
    return out;
}
function cookie(name, value, path, maxAgeSec) {
    return `${name}=${encodeURIComponent(value)}; Path=${path}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}
function inputName(i) {
    return `field-${i}`;
}
function outputKey(f, i) {
    return f.fieldName?.trim() || f.fieldLabel || inputName(i);
}
// ---------- HTML ----------
function page(title, body) {
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f6f8;margin:0;padding:32px 16px;color:#222}
.card{max-width:560px;margin:0 auto;background:#fff;border-radius:8px;padding:28px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
h1{margin-top:0;font-size:22px}label{display:block;font-weight:600;margin:16px 0 6px}
input[type=text],input[type=number],input[type=email],input[type=password],input[type=date],select,textarea{width:100%;box-sizing:border-box;padding:9px;border:1px solid #c8ccd2;border-radius:6px;font-size:14px}
.opt{font-weight:400;display:block;margin:4px 0}.who{color:#666;font-size:13px;margin-bottom:8px}
button{margin-top:22px;background:#0f6cbd;color:#fff;border:0;border-radius:6px;padding:10px 20px;font-size:15px;cursor:pointer}
</style></head><body><div class="card">${body}</div></body></html>`;
}
function renderField(f, i) {
    const name = inputName(i);
    const label = esc(f.fieldLabel);
    const req = f.requiredField ? ' required' : '';
    const ph = f.placeholder ? ` placeholder="${esc(f.placeholder)}"` : '';
    const def = f.defaultValue ? ` value="${esc(f.defaultValue)}"` : '';
    const options = (f.fieldOptions?.values ?? []).map((v) => v.option);
    const wrap = (inner) => `<label>${label}${f.requiredField ? ' *' : ''}</label>${inner}`;
    switch (f.fieldType) {
        case 'html':
            return f.html ?? ''; // trusted: authored by the workflow owner
        case 'hidden':
            return `<input type="hidden" name="${name}" value="${esc(f.defaultValue)}">`;
        case 'textarea':
            return wrap(`<textarea name="${name}" rows="4"${ph}${req}>${esc(f.defaultValue)}</textarea>`);
        case 'dropdown':
            return wrap(`<select name="${name}"${req}><option value="">-- select --</option>${options
                .map((o) => `<option value="${esc(o)}">${esc(o)}</option>`)
                .join('')}</select>`);
        case 'radio':
            return wrap(options
                .map((o) => `<label class="opt"><input type="radio" name="${name}" value="${esc(o)}"${req}> ${esc(o)}</label>`)
                .join(''));
        case 'checkbox':
            return wrap(options
                .map((o) => `<label class="opt"><input type="checkbox" name="${name}" value="${esc(o)}"> ${esc(o)}</label>`)
                .join(''));
        case 'file':
            return wrap(`<input type="file" name="${name}"${f.multipleFiles ? ' multiple' : ''}${f.acceptFileTypes ? ` accept="${esc(f.acceptFileTypes)}"` : ''}${req}>`);
        default: {
            const type = ['text', 'number', 'email', 'password', 'date'].includes(f.fieldType) ? f.fieldType : 'text';
            return wrap(`<input type="${type}" name="${name}"${ph}${def}${req}>`);
        }
    }
}
// ---------- node ----------
class MicrosoftSsoForm {
    constructor() {
        this.description = {
            displayName: 'Form Trigger (Microsoft SSO)',
            name: 'microsoftSsoForm',
            icon: 'file:microsoft.svg',
            group: ['trigger'],
            version: 1,
            description: 'Serve a form that requires Microsoft Entra ID sign-in, optionally restricted to groups',
            defaults: { name: 'Form Trigger (Microsoft SSO)' },
            inputs: [],
            outputs: ['main'],
            credentials: [{ name: 'microsoftSsoFormApi', required: true }],
            webhooks: [
                {
                    name: 'setup',
                    httpMethod: 'GET',
                    responseMode: 'onReceived',
                    path: '={{$parameter["path"]}}',
                    isFullPath: true,
                },
                {
                    name: 'default',
                    httpMethod: 'POST',
                    responseMode: 'onReceived',
                    path: '={{$parameter["path"]}}',
                    isFullPath: true,
                },
            ],
            properties: [
                {
                    displayName: 'Register this node\'s form URL (Test and Production, shown on the node) as a Web redirect URI in your Entra app registration. Microsoft redirects back to the same URL after sign-in.',
                    name: 'notice',
                    type: 'notice',
                    default: '',
                },
                {
                    displayName: 'Path',
                    name: 'path',
                    type: 'string',
                    default: 'ms-form',
                    required: true,
                    description: 'URL path of the form',
                },
                { displayName: 'Form Title', name: 'formTitle', type: 'string', default: 'My Form' },
                { displayName: 'Form Description', name: 'formDescription', type: 'string', default: '' },
                {
                    displayName: 'Form Fields',
                    name: 'formFields',
                    placeholder: 'Add Form Field',
                    type: 'fixedCollection',
                    default: { values: [{ fieldLabel: '', fieldType: 'text' }] },
                    typeOptions: { multipleValues: true },
                    options: [
                        {
                            displayName: 'Values',
                            name: 'values',
                            values: [
                                { displayName: 'Field Label', name: 'fieldLabel', type: 'string', default: '', required: true },
                                {
                                    displayName: 'Field Name',
                                    name: 'fieldName',
                                    type: 'string',
                                    default: '',
                                    description: 'Key in the output JSON. Defaults to the label if empty.',
                                },
                                {
                                    displayName: 'Field Type',
                                    name: 'fieldType',
                                    type: 'options',
                                    default: 'text',
                                    options: [
                                        { name: 'Checkbox', value: 'checkbox' },
                                        { name: 'Custom HTML', value: 'html' },
                                        { name: 'Date', value: 'date' },
                                        { name: 'Dropdown List', value: 'dropdown' },
                                        { name: 'Email', value: 'email' },
                                        { name: 'File', value: 'file' },
                                        { name: 'Hidden Field', value: 'hidden' },
                                        { name: 'Number', value: 'number' },
                                        { name: 'Password', value: 'password' },
                                        { name: 'Radio Buttons', value: 'radio' },
                                        { name: 'Text', value: 'text' },
                                        { name: 'Textarea', value: 'textarea' },
                                    ],
                                },
                                {
                                    displayName: 'Placeholder',
                                    name: 'placeholder',
                                    type: 'string',
                                    default: '',
                                    displayOptions: { show: { fieldType: ['text', 'number', 'email', 'password', 'textarea'] } },
                                },
                                {
                                    displayName: 'Default Value',
                                    name: 'defaultValue',
                                    type: 'string',
                                    default: '',
                                    displayOptions: {
                                        show: { fieldType: ['text', 'number', 'email', 'password', 'textarea', 'date', 'hidden'] },
                                    },
                                },
                                {
                                    displayName: 'Field Options',
                                    name: 'fieldOptions',
                                    placeholder: 'Add Option',
                                    type: 'fixedCollection',
                                    default: { values: [{ option: '' }] },
                                    typeOptions: { multipleValues: true },
                                    displayOptions: { show: { fieldType: ['dropdown', 'radio', 'checkbox'] } },
                                    options: [
                                        {
                                            displayName: 'Values',
                                            name: 'values',
                                            values: [{ displayName: 'Option', name: 'option', type: 'string', default: '' }],
                                        },
                                    ],
                                },
                                {
                                    displayName: 'HTML',
                                    name: 'html',
                                    type: 'string',
                                    typeOptions: { rows: 5 },
                                    default: '',
                                    displayOptions: { show: { fieldType: ['html'] } },
                                },
                                {
                                    displayName: 'Accepted File Types',
                                    name: 'acceptFileTypes',
                                    type: 'string',
                                    default: '',
                                    placeholder: '.pdf, .png',
                                    displayOptions: { show: { fieldType: ['file'] } },
                                },
                                {
                                    displayName: 'Multiple Files',
                                    name: 'multipleFiles',
                                    type: 'boolean',
                                    default: true,
                                    displayOptions: { show: { fieldType: ['file'] } },
                                },
                                {
                                    displayName: 'Required Field',
                                    name: 'requiredField',
                                    type: 'boolean',
                                    default: false,
                                    displayOptions: { hide: { fieldType: ['html', 'hidden'] } },
                                },
                            ],
                        },
                    ],
                },
                { displayName: 'Submit Button Label', name: 'buttonLabel', type: 'string', default: 'Submit' },
                {
                    displayName: 'Completion Message',
                    name: 'completionMessage',
                    type: 'string',
                    default: 'Your response has been recorded.',
                },
                {
                    displayName: 'Access Control',
                    name: 'accessControl',
                    type: 'collection',
                    placeholder: 'Add Restriction',
                    default: {},
                    options: [
                        {
                            displayName: 'Allowed Email Domain',
                            name: 'allowedDomain',
                            type: 'string',
                            default: '',
                            placeholder: 'example.com',
                            description: 'Only users whose email ends with this domain may submit',
                        },
                        {
                            displayName: 'Allowed Group Object IDs',
                            name: 'allowedGroups',
                            type: 'string',
                            default: '',
                            description: 'Comma-separated Entra group Object IDs. User must be a member of at least one. Needs Graph User.Read and, for >200 groups, works via checkMemberGroups.',
                        },
                        {
                            displayName: 'Session TTL (Minutes)',
                            name: 'sessionTtl',
                            type: 'number',
                            default: 30,
                            typeOptions: { minValue: 1, maxValue: 480 },
                        },
                    ],
                },
            ],
        };
    }
    async webhook() {
        const req = this.getRequestObject();
        const res = this.getResponseObject();
        const creds = (await this.getCredentials('microsoftSsoFormApi'));
        if (!creds.sessionSecret || creds.sessionSecret.length < 32) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Session Secret must be at least 32 characters');
        }
        if (!/^[0-9a-f-]{36}$/i.test(creds.tenantId.trim())) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Tenant ID must be the tenant GUID');
        }
        const tenantId = creds.tenantId.trim();
        const access = this.getNodeParameter('accessControl', {});
        const ttlMs = (access.sessionTtl ?? 30) * 60 * 1000;
        const allowedGroups = (access.allowedGroups ?? '')
            .split(',')
            .map((g) => g.trim().toLowerCase())
            .filter(Boolean);
        const allowedDomain = (access.allowedDomain ?? '').trim().toLowerCase().replace(/^@/, '');
        const redirectOverride = (creds.redirectUri ?? '').trim();
        const formUrl = redirectOverride || this.getNodeWebhookUrl('setup');
        const callbackUrl = formUrl;
        const cookiePath = new URL(formUrl).pathname;
        const cookies = parseCookies(req.headers.cookie);
        const session = verify(cookies[SESSION_COOKIE], creds.sessionSecret);
        const send = (status, html, extra = []) => {
            res.status(status);
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('X-Frame-Options', 'DENY');
            if (extra.length)
                res.setHeader('Set-Cookie', extra);
            res.send(html);
            return { noWebhookResponse: true };
        };
        const redirect = (url, extra = []) => {
            res.status(302);
            res.setHeader('Location', url);
            res.setHeader('Cache-Control', 'no-store');
            if (extra.length)
                res.setHeader('Set-Cookie', extra);
            res.end();
            return { noWebhookResponse: true };
        };
        const denied = (msg) => send(403, page('Access denied', `<h1>Access denied</h1><p>${esc(msg)}</p>`));
        // ---- OIDC callback ----
        const q = req.query;
        if (req.method === 'GET' && (q.code || q.error)) {
            if (q.error)
                return denied(`Sign-in failed: ${q.error_description ?? q.error}`);
            const login = verify(cookies[LOGIN_COOKIE], creds.sessionSecret);
            if (!login || !q.code || q.state !== login.state)
                return denied('Invalid or expired sign-in attempt. Please retry.');
            let tokenRes;
            try {
                tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        client_id: creds.clientId,
                        client_secret: creds.clientSecret,
                        grant_type: 'authorization_code',
                        code: q.code,
                        redirect_uri: callbackUrl,
                        code_verifier: login.verifier,
                        scope: SCOPES,
                    }),
                });
            }
            catch (e) {
                const cause = e.cause;
                return denied(`Token exchange request failed: ${e.message}${cause ? ` (${cause.code ?? ''} ${cause.message ?? ''})` : ''}`);
            }
            let tokens;
            try {
                tokens = (await tokenRes.json());
            }
            catch (e) {
                return denied(`Token exchange returned an invalid response (HTTP ${tokenRes.status}).`);
            }
            if (!tokenRes.ok || !tokens.id_token)
                return denied(`Token exchange failed: ${tokens.error_description ?? tokenRes.status}`);
            let claims;
            try {
                const jwks = (0, jose_1.createRemoteJWKSet)(new URL(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`));
                const { payload } = await (0, jose_1.jwtVerify)(tokens.id_token, jwks, {
                    issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
                    audience: creds.clientId,
                });
                claims = payload;
            }
            catch (e) {
                return denied('ID token validation failed.');
            }
            if (claims.nonce !== login.nonce || claims.tid !== tenantId)
                return denied('ID token validation failed.');
            const email = String(claims.email ?? claims.preferred_username ?? '');
            if (allowedDomain && !email.toLowerCase().endsWith(`@${allowedDomain}`)) {
                return denied('Your email domain is not allowed to use this form.');
            }
            let groups = Array.isArray(claims.groups) ? claims.groups.map((g) => g.toLowerCase()) : [];
            if (allowedGroups.length) {
                const overage = claims._claim_names?.groups !== undefined;
                if (overage || !Array.isArray(claims.groups)) {
                    // Too many groups for the token (or groups claim not configured): ask Graph.
                    if (!tokens.access_token)
                        return denied('Unable to verify group membership.');
                    const g = await fetch('https://graph.microsoft.com/v1.0/me/checkMemberGroups', {
                        method: 'POST',
                        headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ groupIds: allowedGroups }),
                    });
                    if (!g.ok)
                        return denied('Unable to verify group membership.');
                    groups = (await g.json()).value.map((x) => x.toLowerCase());
                }
                if (!allowedGroups.some((id) => groups.includes(id))) {
                    return denied('You are not a member of a group permitted to use this form.');
                }
            }
            const newSession = {
                oid: String(claims.oid ?? ''),
                name: String(claims.name ?? ''),
                email,
                tenantId,
                groups: allowedGroups.length ? groups.filter((x) => allowedGroups.includes(x)) : groups,
                csrf: randomString(24),
                exp: Date.now() + ttlMs,
            };
            return redirect(formUrl, [
                cookie(SESSION_COOKIE, sign(newSession, creds.sessionSecret), cookiePath, Math.floor(ttlMs / 1000)),
                cookie(LOGIN_COOKIE, '', cookiePath, 0),
            ]);
        }
        // ---- GET form: start login if no session ----
        if (!session) {
            const state = randomString(16);
            const nonce = randomString(16);
            const verifier = randomString(48);
            const challenge = b64url(crypto_1.default.createHash('sha256').update(verifier).digest());
            const loginCookie = sign({ state, nonce, verifier, exp: Date.now() + 10 * 60 * 1000 }, creds.sessionSecret);
            const authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?` +
                new URLSearchParams({
                    client_id: creds.clientId,
                    response_type: 'code',
                    redirect_uri: callbackUrl,
                    response_mode: 'query',
                    scope: SCOPES,
                    state,
                    nonce,
                    code_challenge: challenge,
                    code_challenge_method: 'S256',
                }).toString();
            if (req.method === 'POST')
                return denied('Session expired. Reload the form and sign in again.');
            return redirect(authUrl, [cookie(LOGIN_COOKIE, loginCookie, cookiePath, 600)]);
        }
        const fields = this.getNodeParameter('formFields.values', []) ?? [];
        const resetEnabled = this.getNodeParameter('enablePasswordReset', true);
        const minLen = this.getNodeParameter('minPasswordLength', 8);
        const blank = (f) => !f.fieldLabel && !f.fieldName && f.fieldType !== 'html';
        const header = (links) => `<div class="who"><strong>Signed in as ${esc(session.email)}</strong>${session.name ? ` (${esc(session.name)})` : ''}<br>${links}</div>`;
        // ---- GET: sign out / reset page / form ----
        if (req.method === 'GET') {
            if (q.action === 'logout')
                return redirect(formUrl, [cookie(SESSION_COOKIE, '', cookiePath, 0)]);
            if (resetEnabled && q.action === 'reset') {
                return send(200, page('Reset password', `<h1>Reset password</h1>${header(`<a href="${esc(formUrl)}">Back</a> · <a href="${esc(formUrl)}?action=logout">Sign out</a>`)}
<form method="POST" action="${esc(formUrl)}">
<input type="hidden" name="_csrf" value="${esc(session.csrf)}">
<input type="hidden" name="_action" value="passwordReset">
<label>New password *</label><input type="password" name="newPassword" minlength="${minLen}" autocomplete="new-password" required>
<label>Confirm password *</label><input type="password" name="confirmPassword" minlength="${minLen}" autocomplete="new-password" required>
<button type="submit">Save</button></form>`));
            }
            const title = this.getNodeParameter('formTitle', '');
            const desc = this.getNodeParameter('formDescription', '');
            const button = this.getNodeParameter('buttonLabel', 'Submit');
            const hasFile = fields.some((f) => f.fieldType === 'file');
            const visible = fields.map((f, i) => (blank(f) ? '' : renderField(f, i))).join('\n');
            const links = (resetEnabled ? `<a href="${esc(formUrl)}?action=reset">Reset password</a> · ` : '') +
                `<a href="${esc(formUrl)}?action=logout">Sign out</a>`;
            const formHtml = visible.trim()
                ? `<form method="POST" action="${esc(formUrl)}"${hasFile ? ' enctype="multipart/form-data"' : ''}>
<input type="hidden" name="_csrf" value="${esc(session.csrf)}">
${visible}
<button type="submit">${esc(button)}</button></form>`
                : '';
            return send(200, page(title, `<h1>${esc(title)}</h1>${header(links)}<p>${esc(desc)}</p>${formHtml}`));
        }
        // ---- POST: submit ----
        const body = (req.body ?? {});
        const data = (body.data && typeof body.data === 'object' ? body.data : body);
        if (data._csrf !== session.csrf)
            return denied('Invalid form token. Reload the form and try again.');
        const userInfo = {
            oid: session.oid,
            name: session.name,
            email: session.email,
            tenantId: session.tenantId,
            groups: session.groups,
        };
        if (data._action === 'passwordReset') {
            if (!resetEnabled)
                return denied('Password reset is not enabled.');
            const newPassword = String(data.newPassword ?? '');
            if (newPassword.length < minLen)
                return denied(`Password must be at least ${minLen} characters.`);
            if (newPassword !== String(data.confirmPassword ?? ''))
                return denied('Passwords do not match.');
            send(200, page('Password saved', `<h1>Password saved</h1><p>Your password reset request was submitted.</p>`));
            return {
                noWebhookResponse: true,
                workflowData: [
                    [{ json: { action: 'passwordReset', newPassword, submittedAt: new Date().toISOString(), user: userInfo } }],
                ],
            };
        }
        const json = {};
        const binary = {};
        const reqFiles = (req.files ?? body.files ?? {});
        for (let i = 0; i < fields.length; i++) {
            const f = fields[i];
            if (f.fieldType === 'html' || blank(f))
                continue;
            const key = inputName(i);
            const outKey = outputKey(f, i);
            if (f.fieldType === 'file') {
                const list = [].concat(reqFiles[key] ?? []);
                if (f.requiredField && !list.length)
                    return denied(`${f.fieldLabel} is required.`);
                for (let n = 0; n < list.length; n++) {
                    const file = list[n];
                    const binKey = list.length > 1 ? `${outKey}_${n}` : outKey;
                    binary[binKey] = await this.nodeHelpers.copyBinaryFile(file.filepath, file.originalFilename ?? file.name ?? binKey, file.mimetype ?? file.type);
                }
                continue;
            }
            let value = data[key];
            if (f.fieldType === 'checkbox')
                value = [].concat(value ?? []);
            if (f.requiredField && (value === undefined || value === '' || (Array.isArray(value) && !value.length))) {
                return denied(`${f.fieldLabel} is required.`);
            }
            if (f.fieldType === 'number' && value !== undefined && value !== '')
                value = Number(value);
            json[outKey] = value ?? null;
        }
        json.submittedAt = new Date().toISOString();
        json.action = 'form';
        json.user = userInfo;
        const message = this.getNodeParameter('completionMessage', '');
        send(200, page('Submitted', `<h1>Thank you</h1><p>${esc(message)}</p>`));
        const item = { json };
        if (Object.keys(binary).length)
            item.binary = binary;
        return { noWebhookResponse: true, workflowData: [[item]] };
    }
}
exports.MicrosoftSsoForm = MicrosoftSsoForm;
