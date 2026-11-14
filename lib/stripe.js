const Stripe = require('stripe');
const {
  USD_TO_BDT,
  formatAmount,
  getCheckoutPricing,
  getPlan,
  normalizeBilling,
} = require('./plans');

const secretKey = (
  process.env.STRI_SECRET_KEY ||
  process.env.STRIPE_SECRET_KEY ||
  ''
).trim();
const publishableKey = (
  process.env.STRIP_PUBLISH_KEY ||
  process.env.STRIPE_PUBLISHABLE_KEY ||
  ''
).trim();
const webhookSecret = (process.env.STRIPE_WEBHOOK_SECRET || '').trim();

let stripeClient = null;

function getStripe() {
  if (!secretKey) {
    const error = new Error('Stripe is not configured on the server');
    error.statusCode = 503;
    throw error;
  }
  if (!stripeClient) {
    stripeClient = new Stripe(secretKey);
  }
  return stripeClient;
}

function getCheckoutConfig({ planId, billing } = {}) {
  const plan = getPlan(planId || 'growth');
  if (!plan) return null;

  const billingValue = normalizeBilling(billing);
  const pricing = getCheckoutPricing(plan, billingValue);

  return {
    publishableKey,
    stripeReady: Boolean(secretKey && publishableKey),
    usdToBdt: USD_TO_BDT,
    plan: {
      id: plan.id,
      name: plan.name,
      description: plan.description,
      icon: plan.icon,
      features: plan.features,
      highlighted: plan.highlighted,
      billing: billingValue,
      interval: pricing.interval,
    },
    currencies: [
      {
        currency: 'BDT',
        amount: pricing.bdtAmount,
        display: formatAmount('BDT', pricing.bdtAmount),
      },
      {
        currency: 'USD',
        amount: pricing.usdCents,
        display: formatAmount('USD', pricing.usdCents),
      },
    ],
    defaultCurrency: 'BDT',
  };
}

function getPrice(currency, planId, billing) {
  const config = getCheckoutConfig({ planId, billing });
  if (!config) return null;

  const code = String(currency || 'BDT').toUpperCase();
  return config.currencies.find((item) => item.currency === code) ?? null;
}

/**
 * Retrieves a hosted Stripe Checkout Session by id (source of truth for the
 * success screen). Expands related objects so the client can render the
 * customer email, payment status and amount without a second round-trip.
 */
async function retrieveCheckoutSession(sessionId, expand = ['line_items', 'payment_intent', 'customer']) {
  const session = await getStripe().checkout.sessions.retrieve(sessionId, { expand });
  return session;
}

async function createCheckoutSession({
  planId,
  billing,
  email,
  userId,
}) {
  const plan = getPlan(planId);
  if (!plan) {
    const error = new Error('Plan not found');
    error.statusCode = 404;
    throw error;
  }

  const billingValue = normalizeBilling(billing);
  const pricing = getCheckoutPricing(plan, billingValue);
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';

  const session = await getStripe().checkout.sessions.create({
    mode: 'payment',
    line_items: [
      {
        price_data: {
          currency: 'usd',
          unit_amount: pricing.usdCents,
          product_data: {
            name: `${plan.name} Plan`,
            description: `${plan.description} · ${billingValue}`,
          },
        },
        quantity: 1,
      },
    ],
    success_url: `${baseUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${baseUrl}/checkout/cancel?session_id={CHECKOUT_SESSION_ID}`,
    ...(email ? { customer_email: email } : {}),
    ...(userId ? { client_reference_id: userId } : {}),
    metadata: {
      plan: plan.id,
      planName: plan.name,
      billing: billingValue,
      userId: userId || '',
      email,
    },
  });

  return {
    id: session.id,
    url: session.url,
    amount: pricing.usdCents,
    currency: 'USD',
    planId: plan.id,
    billing: billingValue,
  };
}

module.exports = {
  createCheckoutSession,
  getCheckoutConfig,
  getPrice,
  getStripe,
  publishableKey,
  retrieveCheckoutSession,
  webhookSecret,
};
