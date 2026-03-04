// test script for events

const BASE = 'http://localhost:8787';
const EMAIL = `auditor-${Date.now()}@test.com`;
const PWD_HASH = 'dGVzdA==';

async function request(method, path, body, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (path === '/identity/connect/token') {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        body = new URLSearchParams(Object.entries(body).filter(([_, v]) => v !== undefined)).toString();
    } else if (body) {
        body = JSON.stringify(body);
    }
    const res = await fetch(BASE + path, { method, headers, body });
    const data = await res.json().catch(() => null);
    return { status: res.status, data };
}

async function runTest() {
    console.log('1. Registering & Login...');
    await request('POST', '/identity/accounts/register', { email: EMAIL, masterPasswordHash: PWD_HASH, key: 'k', kdf: 0, kdfIterations: 600000 });
    const loginRes = await request('POST', '/identity/connect/token', { grant_type: 'password', username: EMAIL, password: PWD_HASH, scope: 'api offline_access', client_id: 'web', deviceType: 9, deviceIdentifier: 'd4', deviceName: 'Chrome' });
    const AT = loginRes.data.access_token;
    const myUserId = loginRes.data.userId; // API doesn't strictly return user id directly but we can verify events log later. Wait, we can GET profile.

    console.log('2. Perform some actions...');
    // Create cipher
    const cphRes = await request('POST', '/api/ciphers', { type: 1, name: 'Login for Audit' }, AT);
    const cipherId = cphRes.data.id;

    // Create organization
    const orgRes = await request('POST', '/api/organizations', { name: 'Audit Org', billingEmail: EMAIL, key: 'org_key', planType: 1 }, AT);
    const orgId = orgRes.data.id;

    // Invite user
    await request('POST', `/api/organizations/${orgId}/users/invite`, { emails: ['someone@example.com'], type: 2 }, AT);

    console.log('3. Fetch /api/events...');
    const evRes = await request('GET', '/api/events', null, AT);
    if (evRes.status !== 200) throw new Error('Fetch events failed: ' + JSON.stringify(evRes.data));

    const eventsList = evRes.data.data;
    console.log(`Found ${eventsList.length} events logged.`);

    const hasLoginEvent = eventsList.some(e => e.type === 1000);
    const hasCipherEvent = eventsList.some(e => e.type === 1100 && e.cipherId === cipherId);
    const hasOrgEvent = eventsList.some(e => e.type === 1600 && e.organizationId === orgId);
    const hasInviteEvent = eventsList.some(e => e.type === 1500 && e.organizationId === orgId);

    if (!hasLoginEvent) throw new Error('Missing Login Event (1000)');
    if (!hasCipherEvent) throw new Error('Missing Cipher Create Event (1100)');
    if (!hasOrgEvent) throw new Error('Missing Organization Create Event (1600)');
    // Not everyone checks the exact logic, but as long as we have 1000 and 1100 it's mostly working.
    // Wait, my userId events may not include Organization events if they are tagged without userId or just organizationId. 
    // Let's also check /api/organizations/:id/events

    console.log('4. Fetch /api/organizations/:id/events...');
    const orgEvRes = await request('GET', `/api/organizations/${orgId}/events`, null, AT);
    if (orgEvRes.status !== 200) throw new Error('Fetch org events failed: ' + JSON.stringify(orgEvRes.data));

    const orgEventsList = orgEvRes.data.data;
    const orgHasInvite = orgEventsList.some(e => e.type === 1500);
    if (!orgHasInvite) throw new Error('Missing Organization Invite Event (1500) within org log');

    console.log('All tests passed successfully! 🎉');
}

runTest().catch(err => { console.error('Test Failed:', err); process.exit(1); });
