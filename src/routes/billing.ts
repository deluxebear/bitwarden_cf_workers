import { Hono } from 'hono';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables } from '../types';

const billing = new Hono<{ Bindings: Bindings; Variables: Variables }>();

billing.use('/*', authMiddleware);

function previewTaxResponse(total = 0) {
    return {
        Tax: 0,
        Total: total,
        EffectiveTaxRate: 0,
        TaxableBaseAmount: total,
        TaxAmount: 0,
        TotalAmount: total,
        object: 'previewInvoice',
    };
}

billing.post('/preview-invoice/organizations/subscriptions/purchase', async (c) => {
    const body = await c.req.json<any>().catch(() => ({}));
    const purchase = body?.purchase ?? {};
    const passwordManager = purchase?.passwordManager ?? {};
    const seats = Number(passwordManager.seats ?? 0);
    const additionalStorage = Number(passwordManager.additionalStorage ?? 0);
    const tier = String(purchase.tier ?? '').toLowerCase();

    const annualSeatPrice = tier === 'enterprise' ? 72 : tier === 'teams' ? 48 : 0;
    const total = seats * annualSeatPrice + additionalStorage * 4;
    return c.json(previewTaxResponse(total));
});

billing.post('/preview-invoice/premium/subscriptions/purchase', async (c) => {
    const body = await c.req.json<any>().catch(() => ({}));
    const additionalStorage = Number(body?.additionalStorage ?? 0);
    return c.json(previewTaxResponse(10 + additionalStorage * 4));
});

billing.post('/preview-invoice/organizations/:id/subscription/plan-change', (c) => {
    return c.json(previewTaxResponse(0));
});

billing.post('/preview-invoice/organizations/:id/subscription/update', (c) => {
    return c.json(previewTaxResponse(0));
});

export default billing;
