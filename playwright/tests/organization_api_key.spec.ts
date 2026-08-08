import { test, expect, type APIRequestContext, type TestInfo } from '@playwright/test';

import * as utils from '../global-utils';

const users = utils.loadEnv();
const masterPasswordHash = 'playwright-master-password-hash';

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Rotating an organization API key revokes existing import bearer tokens', async ({ request }) => {
    const owner = users.user1;
    const nonce = Date.now();
    const ownerEmail = `org-api-key-${nonce}-${owner.email}`;

    await registerUser(request, ownerEmail, owner.name, masterPasswordHash);

    const ownerToken = await loginUser(request, ownerEmail, masterPasswordHash, `owner-${nonce}`);
    const orgId = await createOrganization(request, ownerToken, ownerEmail, nonce);

    const originalApiKey = await getOrganizationApiKey(request, ownerToken, orgId, masterPasswordHash);
    const staleToken = await loginOrganizationApiKey(request, orgId, originalApiKey, `stale-${nonce}`);

    const rotatedApiKey = await rotateOrganizationApiKey(request, ownerToken, orgId, masterPasswordHash);

    const staleEmail = `stale-import-${nonce}@example.test`;
    const staleImport = await importMember(request, staleToken, staleEmail, `stale-${nonce}`);

    expect([401, 403], 'a pre-rotation bearer must be rejected after organization API-key rotation').toContain(
        staleImport.status(),
    );
    await expectMemberAbsent(request, ownerToken, orgId, staleEmail);

    const freshToken = await loginOrganizationApiKey(request, orgId, rotatedApiKey, `fresh-${nonce}`);
    const freshEmail = `fresh-import-${nonce}@example.test`;
    const freshImport = await importMember(request, freshToken, freshEmail, `fresh-${nonce}`);

    expect(freshImport.status(), 'a post-rotation bearer must still import members').toBe(200);
    await expectMemberPresent(request, ownerToken, orgId, freshEmail);
});

async function registerUser(request: APIRequestContext, email: string, name: string, passwordHash: string) {
    const response = await request.post('/identity/accounts/register', {
        data: {
            email,
            name,
            masterPasswordHash: passwordHash,
            masterPasswordHint: null,
            key: 'test-user-key',
            kdf: 0,
            kdfIterations: 600000,
            kdfMemory: null,
            kdfParallelism: null,
        },
    });

    expect(response.status(), await response.text()).toBe(200);
}

async function loginUser(request: APIRequestContext, email: string, password: string, deviceIdentifier: string) {
    const response = await request.post('/identity/connect/token', {
        form: {
            grant_type: 'password',
            scope: 'api offline_access',
            client_id: 'web',
            username: email,
            password,
            device_identifier: deviceIdentifier,
            device_name: 'Playwright organization API key test',
            device_type: '9',
        },
    });

    expect(response.status(), await response.text()).toBe(200);
    return (await response.json()).access_token as string;
}

async function createOrganization(request: APIRequestContext, ownerToken: string, billingEmail: string, nonce: number) {
    const response = await request.post('/api/organizations', {
        headers: authorizationHeaders(ownerToken),
        data: {
            billingEmail,
            collectionName: `API key rotation collection ${nonce}`,
            key: `test-org-key-${nonce}`,
            name: `API key rotation ${nonce}`,
            planType: 0,
        },
    });

    expect(response.status(), await response.text()).toBe(200);
    const body = await response.json();
    return (body.id ?? body.Id ?? body.uuid ?? body.Uuid) as string;
}

async function getOrganizationApiKey(
    request: APIRequestContext,
    ownerToken: string,
    orgId: string,
    masterPasswordHash: string,
) {
    return organizationApiKeyRequest(request, ownerToken, orgId, masterPasswordHash, 'api-key');
}

async function rotateOrganizationApiKey(
    request: APIRequestContext,
    ownerToken: string,
    orgId: string,
    masterPasswordHash: string,
) {
    return organizationApiKeyRequest(request, ownerToken, orgId, masterPasswordHash, 'rotate-api-key');
}

async function organizationApiKeyRequest(
    request: APIRequestContext,
    ownerToken: string,
    orgId: string,
    masterPasswordHash: string,
    endpoint: 'api-key' | 'rotate-api-key',
) {
    const response = await request.post(`/api/organizations/${orgId}/${endpoint}`, {
        headers: authorizationHeaders(ownerToken),
        data: { masterPasswordHash },
    });

    expect(response.status(), await response.text()).toBe(200);
    return (await response.json()).apiKey as string;
}

async function loginOrganizationApiKey(
    request: APIRequestContext,
    orgId: string,
    apiKey: string,
    deviceIdentifier: string,
) {
    const response = await request.post('/identity/connect/token', {
        form: {
            grant_type: 'client_credentials',
            scope: 'api.organization',
            client_id: `organization.${orgId}`,
            client_secret: apiKey,
            device_identifier: deviceIdentifier,
            device_name: 'Playwright organization import test',
            device_type: '9',
        },
    });

    expect(response.status(), await response.text()).toBe(200);
    return (await response.json()).access_token as string;
}

async function importMember(request: APIRequestContext, token: string, email: string, externalId: string) {
    return request.post('/api/public/organization/import', {
        headers: authorizationHeaders(token),
        data: {
            groups: [],
            members: [{ email, externalId, deleted: false }],
            overwriteExisting: false,
        },
    });
}

async function expectMemberAbsent(request: APIRequestContext, ownerToken: string, orgId: string, email: string) {
    const usersResponse = await listUsers(request, ownerToken, orgId);
    expect(JSON.stringify(await usersResponse.json())).not.toContain(email);
}

async function expectMemberPresent(request: APIRequestContext, ownerToken: string, orgId: string, email: string) {
    const usersResponse = await listUsers(request, ownerToken, orgId);
    expect(JSON.stringify(await usersResponse.json())).toContain(email);
}

async function listUsers(request: APIRequestContext, ownerToken: string, orgId: string) {
    const response = await request.get(`/api/organizations/${orgId}/users`, {
        headers: authorizationHeaders(ownerToken),
    });

    expect(response.status(), await response.text()).toBe(200);
    return response;
}

function authorizationHeaders(token: string) {
    return {
        Authorization: `Bearer ${token}`,
    };
}
