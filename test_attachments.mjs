import fs from 'node:fs';

const BASE = 'http://localhost:8787';
const EMAIL = `auditor-attachment-${Date.now()}@test.com`;
const PWD_HASH = 'dGVzdA==';

async function request(method, path, body, token = null, isFormData = false) {
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    let reqBody = body;
    if (path === '/identity/connect/token') {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        reqBody = new URLSearchParams(Object.entries(body).filter(([_, v]) => v !== undefined)).toString();
    } else if (!isFormData && body) {
        headers['Content-Type'] = 'application/json';
        reqBody = JSON.stringify(body);
    }

    const res = await fetch(BASE + path, { method, headers, body: reqBody });
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return { status: res.status, data: await res.json() };
    } else if (contentType.includes('text/plain') || contentType.includes('application/octet-stream')) {
        return { status: res.status, text: await res.text() };
    } else {
        return { status: res.status };
    }
}

async function runTest() {
    console.log('1. Registering & Login...');
    await request('POST', '/identity/accounts/register', { email: EMAIL, masterPasswordHash: PWD_HASH, key: 'k', kdf: 0, kdfIterations: 600000 });
    const loginRes = await request('POST', '/identity/connect/token', { grant_type: 'password', username: EMAIL, password: PWD_HASH, scope: 'api offline_access', client_id: 'web', deviceType: 9, deviceIdentifier: 'd4', deviceName: 'Chrome' });
    const AT = loginRes.data.access_token;

    console.log('2. Create cipher...');
    const cphRes = await request('POST', '/api/ciphers', { type: 1, name: 'Attachment Test Cipher' }, AT);
    const cipherId = cphRes.data.id;

    if (!cipherId) throw new Error('Failed to create cipher');

    console.log('3. Upload attachment...');
    const formData = new FormData();
    formData.append('data', new Blob(['Hello World! This is an imaginary attachment.'], { type: 'text/plain' }), 'hello.txt');
    formData.append('key', 'fake-encryption-key');
    formData.append('filename', 'hello.txt');

    const uploadRes = await request('POST', `/api/ciphers/${cipherId}/attachment-v2`, formData, AT, true);
    if (uploadRes.status !== 200) throw new Error('Upload failed: ' + JSON.stringify(uploadRes.data));

    const cipherData = uploadRes.data;
    const attachments = cipherData.attachments;
    if (!attachments || attachments.length === 0) throw new Error('Attachments metadata missing in response');

    const att = attachments[0];
    console.log('Got attachment metadata:', att);

    console.log('4. Download attachment...');
    const downloadRes = await request('GET', `/api/ciphers/${cipherId}/attachment/${att.id}`, null, AT);
    if (downloadRes.status !== 200 || downloadRes.text !== 'Hello World! This is an imaginary attachment.') {
        throw new Error(`Download validation failed. HTTP ${downloadRes.status}, Content: ${downloadRes.text}`);
    }

    console.log('5. Delete attachment...');
    const delRes = await request('DELETE', `/api/ciphers/${cipherId}/attachment/${att.id}`, null, AT);
    if (delRes.status !== 200) throw new Error('Delete failed');

    // Verify deletion
    const getCipherRes = await request('GET', `/api/ciphers/${cipherId}`, null, AT);
    if (getCipherRes.data.attachments && getCipherRes.data.attachments.length > 0) {
        throw new Error('Attachment still present in metadata after deletion');
    }

    console.log('All tests passed successfully! 🎉');
}

runTest().catch(err => { console.error('Test Failed:', err); process.exit(1); });
