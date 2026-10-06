import { ICredentialType, INodeProperties } from 'n8n-workflow';

export class MicrosoftSsoFormApi implements ICredentialType {
	name = 'microsoftSsoFormApi';
	displayName = 'Microsoft SSO Form API';
	documentationUrl = 'https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow';
	properties: INodeProperties[] = [
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
