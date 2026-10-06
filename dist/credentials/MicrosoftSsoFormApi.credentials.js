"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MicrosoftSsoFormApi = void 0;
class MicrosoftSsoFormApi {
    constructor() {
        this.name = 'microsoftSsoFormApi';
        this.displayName = 'Microsoft SSO Form API';
        this.documentationUrl = 'https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow';
        this.properties = [
            {
                displayName: 'Tenant ID',
                name: 'tenantId',
                type: 'string',
                default: '',
                required: true,
                description: 'Directory (tenant) ID GUID. "common" or "organizations" are not supported.',
            },
            {
                displayName: 'Client ID',
                name: 'clientId',
                type: 'string',
                default: '',
                required: true,
            },
            {
                displayName: 'Client Secret',
                name: 'clientSecret',
                type: 'string',
                typeOptions: { password: true },
                default: '',
                required: true,
            },
            {
                displayName: 'Session Secret',
                name: 'sessionSecret',
                type: 'string',
                typeOptions: { password: true },
                default: '',
                required: true,
                description: 'At least 32 random characters. Signs the login and session cookies.',
            },
        ];
    }
}
exports.MicrosoftSsoFormApi = MicrosoftSsoFormApi;
