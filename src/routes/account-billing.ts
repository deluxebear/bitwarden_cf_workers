import { Hono } from 'hono';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables } from '../types';

const accountBilling = new Hono<{ Bindings: Bindings; Variables: Variables }>();

accountBilling.use('/*', authMiddleware);

accountBilling.get('/billing/vnext/subscription', (c) => {
    return c.json(null);
});

accountBilling.get('/billing/vnext/credit', (c) => {
    return c.json(null);
});

accountBilling.get('/billing/vnext/address', (c) => {
    return c.json(null);
});

accountBilling.get('/billing/vnext/payment-method', (c) => {
    return c.json(null);
});

accountBilling.get('/billing/vnext/discounts', (c) => {
    return c.json([]);
});

export default accountBilling;
