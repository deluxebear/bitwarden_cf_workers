import { Hono } from 'hono';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables } from '../types';

const setupIntent = new Hono<{ Bindings: Bindings; Variables: Variables }>();

setupIntent.use('/*', authMiddleware);

setupIntent.post('/card', (c) => {
    return c.json('seti_self_hosted_card_secret_placeholder');
});

setupIntent.post('/bank-account', (c) => {
    return c.json('seti_self_hosted_bank_account_secret_placeholder');
});

export default setupIntent;
