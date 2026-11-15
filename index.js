const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { MongoClient, ObjectId } = require('mongodb');
const express = require('express');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const { z } = require('zod');
const { getBetterAuthSessionToken } = require('./lib/better-auth-session');
const {
  createCheckoutSession,
  getCheckoutConfig,
  getPrice,
  getStripe,
  webhookSecret,
} = require('./lib/stripe');
const {
  YEARLY_DISCOUNT,
  USD_TO_BDT,
  FREE_PLAN_APPLICATION_LIMIT,
  getPlan,
  getPlanList,
  getCheckoutPricing,
} = require('./lib/plans');

const { version } = require('./package.json');

const app = express();
const PORT = process.env.PORT || 5000;
const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');
const dbName = process.env.DB_NAME || 'hireloopdb';
const jobsCollectionName = process.env.JOBS_COLLECTION || 'jobs';
const savedJobsCollectionName = process.env.SAVED_JOBS_COLLECTION || 'savedJobs';
const applicationsCollectionName = process.env.APPLICATIONS_COLLECTION || 'applications';
const activitiesCollectionName = process.env.ACTIVITIES_COLLECTION || 'activities';
const paymentsCollectionName = process.env.PAYMENTS_COLLECTION || 'payments';

const defaultAllowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
];

const allowedOrigins = (process.env.CORS_ORIGIN || defaultAllowedOrigins.join(','))
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));
app.options('/{*splat}', cors(corsOptions));

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '100kb' }));

const sanitize = (obj) => {
  if (obj && typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      if (key.startsWith('$') || key.includes('.')) {
        delete obj[key];
      } else {
        sanitize(obj[key]);
      }
    }
  }
  return obj;
};

app.use((req, res, next) => {
  sanitize(req.body);
  sanitize(req.params);
  sanitize(req.query);
  next();
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 200,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again shortly.' },
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
});

const checkoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many checkout attempts. Please try again shortly.' },
});

async function resolveSessionUserFromReq(req, db) {
  const token = getBetterAuthSessionToken(
    req.headers.cookie,
    req.headers.authorization,
    process.env.BETTER_AUTH_SECRET,
  );
  if (!token) return null;

  const session = await db.collection('session').findOne({
    token,
    expiresAt: { $gt: new Date() },
  });
  if (!session?.userId) return null;

  return db.collection('user').findOne({
    $or: [
      { _id: session.userId },
      ...(ObjectId.isValid(String(session.userId))
        ? [{ _id: new ObjectId(String(session.userId)) }]
        : []),
      { id: String(session.userId) },
    ],
  });
}

async function requireSessionAuth(req, res, next) {
  try {
    req.user = await resolveSessionUserFromReq(req, client.db(dbName));
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return next();
  } catch (err) {
    console.error('Session authentication failed:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not verify session' });
  }
}

async function optionalSessionAuth(req, res, next) {
  try {
    req.user = await resolveSessionUserFromReq(req, client.db(dbName));
  } catch (err) {
    console.error('optionalSessionAuth error:', err);
    req.user = null;
  }
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const role = String(req.user?.role ?? '').toLowerCase();
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse({
      body: req.body,
      query: req.query,
      params: req.params,
    });
    if (!result.success) {
      const issues = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
      return res.status(400).json({ error: 'Validation failed', details: issues });
    }
    // Mutate in place — Express 5 makes req.query a read-only getter
    if (result.data.body) Object.assign(req.body, result.data.body);
    if (result.data.query) Object.assign(req.query, result.data.query);
    if (result.data.params) Object.assign(req.params, result.data.params);
    next();
  };
}

const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(50).default(10),
  sort: z.enum(['newest', 'salary']).default('newest'),
});

const jobFiltersQuerySchema = paginationQuerySchema.extend({
  q: z.string().trim().max(200).optional(),
  status: z.enum(['open', 'closed']).optional(),
  type: z.string().optional(),
  workMode: z.string().optional(),
  level: z.string().optional(),
  salaryMin: z.string().optional(),
});

const objectIdParamSchema = z.object({
  params: z.object({
    id: z.string().length(24).regex(/^[0-9a-fA-F]{24}$/),
  }),
});

const saveJobBodySchema = z.object({
  body: z.object({}).strict(),
});

const applyJobBodySchema = z.object({
  body: z.object({}).strict(),
});

const applicationStatusBodySchema = z.object({
  body: z.object({
    status: z.enum([
      'applied', 'new', 'reviewing', 'under_review', 'shortlisted',
      'interview', 'scheduled', 'rejected', 'hired', 'withdrawn'
    ]),
  }),
});

const activityTrackBodySchema = z.object({
  body: z.object({
    event: z.string().min(1).max(100),
    jobId: z.string().length(24).regex(/^[0-9a-fA-F]{24}$/).optional(),
    metadata: z.record(z.unknown()).optional(),
  }),
});

const checkoutConfigQuerySchema = z.object({
  query: z.object({
    plan: z.string().optional(),
    billing: z.enum(['monthly', 'yearly']).optional(),
  }),
});

const paymentIntentBodySchema = z.object({
  body: z.object({
    planId: z.string().min(1).optional(),
    billing: z.enum(['monthly', 'yearly']).optional(),
    currency: z.string().length(3).optional(),
    email: z.string().email().optional(),
  }),
});

const checkoutConfirmBodySchema = z.object({
  body: z.object({
    paymentIntentId: z.string().startsWith('pi_'),
  }),
});

const checkoutSessionBodySchema = z.object({
  body: z.object({
    planId: z.string().min(1).optional(),
    billing: z.enum(['monthly', 'yearly']).optional(),
    email: z.string().email().optional(),
  }),
});

const checkoutSessionParamSchema = z.object({
  params: z.object({
    sessionId: z.string().startsWith('cs_'),
  }),
});

const paymentParamSchema = z.object({
  params: z.object({
    paymentIntentId: z.string().regex(/^(pi_|cs_)/),
  }),
});

const createJobBodySchema = z.object({
  body: z.object({
    title: z.string().trim().min(1).max(200),
    companyName: z.string().trim().min(1).max(200),
    description: z.string().trim().min(1).max(50000),
    location: z.string().trim().min(1).max(200),
    type: z.string().trim().max(50).optional(),
    workMode: z.string().trim().max(50).optional(),
    level: z.string().trim().max(50).optional(),
    salaryMin: z.number().int().min(0).optional(),
    salaryMax: z.number().int().min(0).optional(),
    currency: z.string().length(3).optional(),
    salaryFrequency: z.string().trim().max(20).optional(),
    responsibilities: z.array(z.string().trim().max(500)).max(50).optional(),
    requirements: z.array(z.string().trim().max(500)).max(50).optional(),
    skills: z.array(z.string().trim().max(100)).max(30).optional(),
    benefits: z.array(z.string().trim().max(500)).max(30).optional(),
    applicationDeadline: z.string().datetime().optional(),
    companyOverview: z.string().trim().max(5000).optional(),
    logoUrl: z.string().url().optional(),
    remote: z.boolean().optional(),
    easyApply: z.boolean().optional(),
  }).strict(),
});

const companySlugParamSchema = z.object({
  params: z.object({
    slug: z.string().min(1).max(200),
  }),
});

const billingPortalBodySchema = z.object({
  body: z.object({}).strict(),
});

function paymentStatusFromIntent(intent) {
  if (intent.status === 'succeeded') return 'success';
  if (intent.status === 'canceled' || intent.last_payment_error) return 'failed';
  return 'pending';
}

async function recordPaymentIntent(intent, user = null) {
  const now = new Date();
  const status = paymentStatusFromIntent(intent);
  const userId = user
    ? String(user._id ?? user.id)
    : intent.metadata?.userId || null;
  const userEmail =
    intent.receipt_email || intent.metadata?.email || user?.email || null;

  await client
    .db(dbName)
    .collection(paymentsCollectionName)
    .updateOne(
      { transactionId: intent.id },
      {
        $set: {
          provider: 'stripe',
          transactionId: intent.id,
          paymentIntentId: intent.id,
          userId,
          userName: user?.name ?? null,
          userEmail,
          plan: intent.metadata?.plan || null,
          planName:
            intent.metadata?.planName || intent.description || null,
          billing: intent.metadata?.billing || null,
          amount: intent.amount,
          currency: String(intent.currency ?? '').toUpperCase(),
          status,
          stripeStatus: intent.status,
          updatedAt: now,
        },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true },
    );

  return {
    status,
    stripeStatus: intent.status,
    amount: intent.amount,
    currency: String(intent.currency ?? '').toUpperCase(),
  };
}

app.get('/', (req, res) => {
  res.status(200).json({
    name: 'hireloop API',
    status: 'running',
    version,
    message: 'hireloop API is running',
    time: new Date().toISOString(),
  });
});

app.get('/health', async (req, res) => {
  try {
    await client.db('admin').command({ ping: 1 });
    res.status(200).json({ status: 'ok' });
  } catch (err) {
    res.status(503).json({ status: 'error' });
  }
});

app.post(
  '/api/checkout/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      if (!webhookSecret) {
        return res
          .status(503)
          .json({ error: 'Stripe webhook secret is not configured' });
      }

      const signature = req.headers['stripe-signature'];
      let event;
      try {
        event = getStripe().webhooks.constructEvent(
          req.body,
          signature,
          webhookSecret,
        );
      } catch (err) {
        console.error('Stripe webhook signature error:', err?.message ?? err);
        return res.status(400).json({ error: 'Invalid Stripe signature' });
      }

      const handledEvents = new Set([
        'payment_intent.succeeded',
        'payment_intent.payment_failed',
        'payment_intent.canceled',
        'checkout.session.completed',
        'checkout.session.failed',
        'invoice.paid',
        'invoice.payment_failed',
        'customer.subscription.updated',
        'customer.subscription.deleted',
      ]);
      if (handledEvents.has(event.type) && event.data?.object) {
        if (event.type === 'checkout.session.completed') {
          await recordCheckoutSession(event.data.object);
        } else if (event.type === 'invoice.paid' || event.type === 'invoice.payment_failed') {
          await recordInvoiceEvent(event.data.object, event.type);
        } else if (
          event.type === 'customer.subscription.updated' ||
          event.type === 'customer.subscription.deleted'
        ) {
          await applySubscriptionState(event.data.object);
        } else {
          await recordPaymentIntent(event.data.object);
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error('Stripe webhook error:', err?.message ?? err);
      return res.status(500).json({ error: 'Webhook handler failed' });
    }
  },
);

app.get('/api/plans', (_req, res) => {
  res.json({
    data: {
      usdToBdt: USD_TO_BDT,
      yearlyDiscount: YEARLY_DISCOUNT,
      plans: getPlanList(),
    },
  });
});

app.get('/api/checkout/config', validate(checkoutConfigQuerySchema), (req, res) => {
  const config = getCheckoutConfig({
    planId: req.query.plan,
    billing: req.query.billing,
  });

  if (!config) {
    return res.status(404).json({ error: 'Plan not found' });
  }

  return res.json({ data: config });
});

app.post('/api/checkout/payment-intent', checkoutLimiter, optionalSessionAuth, validate(paymentIntentBodySchema), async (req, res) => {
  try {
    const planId = req.body.planId ?? 'growth';
    const billing = req.body.billing ?? 'monthly';
    const config = getCheckoutConfig({ planId, billing });

    if (!config) {
      return res.status(404).json({ error: 'Plan not found' });
    }
    if (!config.stripeReady) {
      return res.status(503).json({ error: 'Stripe is not configured on the server' });
    }

    const price = getPrice(req.body.currency, planId, billing);
    if (!price) {
      return res.status(400).json({ error: 'Unsupported currency' });
    }
    if (price.amount <= 0) {
      return res.status(400).json({ error: 'This plan is free — no payment is required' });
    }

    const email = req.body.email ?? '';
    const userId = req.user ? String(req.user._id ?? req.user.id) : '';

    const intent = await getStripe().paymentIntents.create({
      amount: price.amount,
      currency: price.currency.toLowerCase(),
      automatic_payment_methods: { enabled: true },
      ...(email ? { receipt_email: email } : {}),
      description: `${config.plan.name} Plan - ${price.display}/${config.plan.interval}`,
      metadata: {
        plan: config.plan.id,
        planName: config.plan.name,
        billing: config.plan.billing,
        displayPrice: price.display,
        userId,
        email,
      },
    });

    return res.status(201).json({
      data: {
        id: intent.id,
        clientSecret: intent.client_secret,
        amount: price.amount,
        currency: price.currency,
        display: price.display,
        planId: config.plan.id,
        billing: config.plan.billing,
        publishableKey: config.publishableKey,
      },
    });
  } catch (err) {
    console.error('POST payment-intent error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 400 : 502);
    return res
      .status(status)
      .json({ error: err?.message || 'Could not start checkout' });
  }
});

app.post('/api/checkout/confirm', checkoutLimiter, optionalSessionAuth, validate(checkoutConfirmBodySchema), async (req, res) => {
  try {
    const paymentIntentId = req.body.paymentIntentId;

    const intent = await getStripe().paymentIntents.retrieve(paymentIntentId);

    const userId = req.user ? String(req.user._id ?? req.user.id) : null;
    if (intent.metadata?.userId && userId && intent.metadata.userId !== userId) {
      return res.status(403).json({ error: 'This payment belongs to another account' });
    }

    if (intent.status !== 'succeeded') {
      await recordPaymentIntent(intent, req.user);
      return res.status(409).json({
        error: `Payment is ${intent.status}`,
        status: intent.status,
      });
    }

    const payment = await recordPaymentIntent(intent, req.user);
    return res.json({
      data: { transactionId: intent.id, ...payment },
    });
  } catch (err) {
    console.error('POST checkout confirm error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 400 : 502);
    return res
      .status(status)
      .json({ error: err?.message || 'Could not verify payment' });
  }
});

app.get('/api/checkout/payments/:paymentIntentId', validate(paymentParamSchema), async (req, res) => {
  try {
    const paymentIntentId = req.params.paymentIntentId;
    const isCheckoutSession = paymentIntentId.startsWith('cs_');

    const payment = await client
      .db(dbName)
      .collection(paymentsCollectionName)
      .findOne({ transactionId: paymentIntentId });

    if (payment) {
      return res.json({
        data: {
          transactionId: payment.transactionId,
          userEmail: payment.userEmail ?? null,
          plan: payment.plan ?? null,
          planName: payment.planName ?? null,
          billing: payment.billing ?? null,
          interval: payment.interval ?? null,
          amount: payment.amount ?? null,
          currency: payment.currency ?? null,
          status: payment.status ?? null,
          stripeStatus: payment.stripeStatus ?? null,
          createdAt: payment.createdAt
            ? new Date(payment.createdAt).toISOString()
            : null,
        },
      });
    }

    if (isCheckoutSession) {
      try {
        const session = await getStripe().checkout.sessions.retrieve(paymentIntentId, {
          expand: ['line_items', 'payment_intent', 'customer'],
        });
        const data = buildCheckoutSessionData(session, null);
        return res.json({ data });
      } catch (sessionErr) {
        console.error('GET checkout session fallback error:', sessionErr?.message ?? sessionErr);
      }
    }

    return res.status(404).json({ error: 'Payment not found' });
  } catch (err) {
    console.error('GET checkout payment error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 400 : 502);
    return res
      .status(status)
      .json({ error: err?.message || 'Could not load payment' });
  }
});

function buildCheckoutSessionData(session, user = null) {
  const paid = session.payment_status === 'paid';
  const metadata = session.metadata || {};
  const billing = metadata.billing || null;

  return {
    id: session.id,
    transactionId: session.id,
    paymentIntentId: session.payment_intent ? String(session.payment_intent) : null,
    url: session.url || null,
    amount: session.amount_total ?? 0,
    currency: String(session.currency ?? 'USD').toUpperCase(),
    status: paid ? 'success' : String(session.payment_status || 'pending'),
    stripeStatus: session.status,
    customerEmail:
      session.customer_details?.email ||
      session.customer_email ||
      session.customer?.email ||
      metadata.email ||
      user?.email ||
      null,
    plan: metadata.plan || null,
    planName: metadata.planName || null,
    billing,
    interval: billing === 'yearly' ? 'year' : billing === 'monthly' ? 'month' : null,
    receiptUrl: session.receipt_url || null,
    createdAt: session.created_at ? new Date(session.created_at * 1000).toISOString() : null,
  };
}

async function recordCheckoutSession(session, user = null) {
  const now = new Date();
  const status =
    session.payment_status === 'paid' || session.status === 'complete'
      ? 'success'
      : 'pending';

  const payment = {
    provider: 'stripe',
    transactionId: session.id,
    paymentIntentId: session.payment_intent ? String(session.payment_intent) : null,
    userId: user ? String(user._id ?? user.id) : session.metadata?.userId || null,
    userName: user?.name ?? null,
    userEmail:
      session.customer_details?.email ||
      session.customer_email ||
      session.metadata?.email ||
      null,
    stripeCustomerId: typeof session.customer === 'string' ? session.customer : session.customer?.id ?? null,
    subscriptionId: session.subscription ?? null,
    plan: session.metadata?.plan || null,
    planName: session.metadata?.planName || null,
    billing: session.metadata?.billing || null,
    interval:
      session.metadata?.billing === 'yearly'
        ? 'year'
        : session.metadata?.billing === 'monthly'
          ? 'month'
          : null,
    amount: session.amount_total ?? 0,
    currency: String(session.currency ?? 'USD').toUpperCase(),
    status,
    stripeStatus: session.status,
    receiptUrl: session.receipt_url || null,
    updatedAt: now,
  };

  await client
    .db(dbName)
    .collection(paymentsCollectionName)
    .updateOne(
      { transactionId: session.id },
      {
        $set: payment,
        $setOnInsert: { createdAt: now },
      },
      { upsert: true },
    );

  const data = buildCheckoutSessionData(session, user);

  return {
    status: data.status,
    stripeStatus: data.stripeStatus,
    amount: data.amount,
    currency: data.currency,
    transactionId: data.transactionId,
    paymentIntentId: data.paymentIntentId,
    customerEmail: data.customerEmail,
    plan: data.plan,
    planName: data.planName,
    billing: data.billing,
    interval: data.interval,
    receiptUrl: data.receiptUrl,
  };
}

app.get('/api/checkout/session/:sessionId', optionalSessionAuth, validate(checkoutSessionParamSchema), async (req, res) => {
  try {
    const sessionId = req.params.sessionId;

    const session = await getStripe().checkout.sessions.retrieve(sessionId, {
      expand: ['line_items', 'payment_intent', 'customer'],
    });

    if (session.payment_status === 'paid' || session.status === 'complete') {
      try {
        await recordCheckoutSession(session, req.user || null);
      } catch (recErr) {
        console.error('recordCheckoutSession from GET error:', recErr?.message ?? recErr);
      }
    }

    const data = buildCheckoutSessionData(session, req.user || null);

    return res.json({ data });
  } catch (err) {
    console.error('GET checkout session error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 404 : 502);
return res.status(status).json({ error: err?.message || 'Could not load checkout session' });
  }
});

app.post('/api/checkout/session', checkoutLimiter, optionalSessionAuth, validate(checkoutSessionBodySchema), async (req, res) => {
  try {
    const config = getCheckoutConfig({
      planId: req.body.planId,
      billing: req.body.billing,
    });

    if (!config) {
      return res.status(404).json({ error: 'Plan not found' });
    }

    const planId = config.plan.id;
    const billing = config.plan.billing;
    const price = getPrice('USD', planId, billing);

    if (!price) {
      return res.status(400).json({ error: 'Unsupported currency' });
    }
    if (price.amount <= 0) {
      return res.status(400).json({ error: 'This plan is free — no checkout required' });
    }

    const email = req.body.email ?? '';
    const userId = req.user ? String(req.user._id ?? req.user.id) : '';
    const session = await createCheckoutSession({
      planId,
      billing,
      email,
      userId,
    });

    return res.status(201).json({
      data: {
        id: session.id,
        url: session.url,
        amount: session.amount,
        currency: session.currency,
        planId: session.planId,
        billing: session.billing,
      },
    });
  } catch (err) {
    console.error('POST checkout session error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 400 : 502);
    return res
      .status(status)
      .json({ error: err?.message || 'Could not create checkout session' });
  }
});

app.get('/api/billing/summary', requireSessionAuth, async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const db = client.db(dbName);
    const userIds = [userId];
    if (ObjectId.isValid(userId)) {
      userIds.push(new ObjectId(userId));
    }
    const userOrEmailFilter = {
      $or: [
        { userId: { $in: userIds } },
        ...(req.user.email
          ? [
              { userEmail: req.user.email },
              { customerEmail: req.user.email },
              { 'metadata.email': req.user.email },
            ]
          : []),
      ],
    };

    const latest = await db
      .collection(paymentsCollectionName)
      .findOne(userOrEmailFilter, { sort: { createdAt: -1 } });

    let status = 'Active';
    let renewalDate = null;
    let cancelAtPeriodEnd = false;
    let paymentMethod = null;
    let stripeCustomerId = latest?.stripeCustomerId ?? null;

    let currentPlan = null;

    if (latest && latest.plan && latest.plan !== 'starter') {
      const planConfig = getPlan(latest.plan);
      const isYearly = latest.interval === 'year' || latest.billing === 'yearly';
      let calculatedAmount = latest.amount ?? 0;
      if (!calculatedAmount && planConfig) {
        calculatedAmount = isYearly
          ? getCheckoutPricing(planConfig, 'yearly').usdCents
          : planConfig.monthlyPrice * 100;
      }

      currentPlan = {
        id: latest.plan ?? null,
        name: latest.planName ?? planConfig?.name ?? latest.plan ?? 'Pro',
        interval: isYearly ? 'year' : 'month',
        amount: calculatedAmount,
        currency: String(latest.currency ?? 'USD').toUpperCase(),
        status: latest.status ?? 'Active',
        features: planConfig?.features ?? [
          'Unlimited job applications',
          'Premium job insights',
          'Priority candidate badge',
          'Direct recruiter messaging',
        ],
        isFree: false,
      };

      if (latest.subscriptionId) {
        try {
          const subscription = await getStripe().subscriptions.retrieve(latest.subscriptionId, {
            expand: ['customer'],
          });
          renewalDate = subscription.current_period_end
            ? new Date(subscription.current_period_end * 1000).toISOString()
            : null;
          cancelAtPeriodEnd = Boolean(subscription.cancel_at_period_end);
          status =
            subscription.status === 'canceled'
              ? 'Canceled'
              : subscription.status === 'past_due'
                ? 'Past due'
                : 'Active';
        } catch (subErr) {
          console.error('billing subscription retrieve error:', subErr?.message ?? subErr);
          status = latest.status === 'failed' ? 'Past due' : 'Active';
        }
      } else if (latest.status) {
        status = latest.status === 'success' ? 'Active' : latest.status === 'failed' ? 'Past due' : 'Pending';
      }

      if (!renewalDate && latest.createdAt) {
        const nextDate = new Date(latest.createdAt);
        if (isYearly) {
          nextDate.setFullYear(nextDate.getFullYear() + 1);
        } else {
          nextDate.setMonth(nextDate.getMonth() + 1);
        }
        renewalDate = nextDate.toISOString();
      }
    } else {
      const freePlan = getPlan('starter');
      currentPlan = {
        id: 'starter',
        name: freePlan ? freePlan.name : 'Starter',
        interval: 'month',
        amount: 0,
        currency: 'USD',
        status: 'Active',
        features: freePlan?.features ?? [
          'Daily AI match brief (top 5)',
          'Verified salary bands',
          'Company insight dashboards',
          '1-click apply, unlimited',
        ],
        isFree: true,
      };
      status = 'Active';
    }

    const applicationCountForSummary = await db
      .collection(applicationsCollectionName)
      .countDocuments({
        $or: [
          { userId: { $in: userIds } },
          { seekerId: { $in: userIds } },
        ],
      });
    const isFreePlanForSummary = !currentPlan || currentPlan.id === 'starter';
    const remainingApplications = isFreePlanForSummary
      ? Math.max(0, FREE_PLAN_APPLICATION_LIMIT - applicationCountForSummary)
      : null;

    if (!stripeCustomerId && req.user.email) {
      try {
        const customers = await getStripe().customers.list({
          email: req.user.email,
          limit: 1,
        });
        if (customers.data.length > 0) {
          stripeCustomerId = customers.data[0].id;
          if (latest) {
            await db
              .collection(paymentsCollectionName)
              .updateOne({ _id: latest._id }, { $set: { stripeCustomerId } });
          }
        }
      } catch (custErr) {}
    }

    if (stripeCustomerId) {
      try {
        const customer = await getStripe().customers.retrieve(stripeCustomerId, {
          expand: ['default_payment_method'],
        });
        let pm = customer.default_payment_method;
        if (!pm) {
          const pmList = await getStripe().paymentMethods.list({
            customer: stripeCustomerId,
            type: 'card',
            limit: 1,
          });
          if (pmList.data.length > 0) {
            pm = pmList.data[0];
          }
        }
        if (pm) {
          paymentMethod = {
            brand: pm.card?.brand ?? pm.type ?? null,
            last4: pm.card?.last4 ?? null,
            expMonth: pm.card?.exp_month ?? null,
            expYear: pm.card?.exp_year ?? null,
          };
        }
      } catch (pmErr) {
        console.error('billing payment method retrieve error:', pmErr?.message ?? pmErr);
      }
    }

    return res.json({
      data: {
        currentPlan,
        billingInterval: currentPlan?.interval ?? 'month',
        price: currentPlan?.amount ?? 0,
        currency: currentPlan?.currency ?? 'USD',
        status,
        renewalDate,
        cancelAtPeriodEnd,
        paymentMethod,
        hasStripeCustomer: Boolean(stripeCustomerId),
        stripeCustomerId,
        freePlanApplicationLimit: isFreePlanForSummary ? FREE_PLAN_APPLICATION_LIMIT : null,
        applicationCount: applicationCountForSummary,
        remainingApplications,
      },
    });
  } catch (err) {
    console.error('GET billing summary error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 502 : 500);
    return res.status(status).json({ error: err?.message || 'Could not load billing summary' });
  }
});

app.get('/api/billing/history', requireSessionAuth, async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const db = client.db(dbName);
    const userIds = [userId];
    if (ObjectId.isValid(userId)) {
      userIds.push(new ObjectId(userId));
    }
    const userOrEmailFilter = {
      $or: [
        { userId: { $in: userIds } },
        ...(req.user.email
          ? [
              { userEmail: req.user.email },
              { customerEmail: req.user.email },
              { 'metadata.email': req.user.email },
            ]
          : []),
      ],
    };

    const docs = await db
      .collection(paymentsCollectionName)
      .find(userOrEmailFilter)
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    const statusMap = { success: 'paid', pending: 'pending', failed: 'failed' };
    const history = docs.map((doc) => ({
      id: doc.transactionId ?? (doc._id ? String(doc._id) : null),
      date: doc.createdAt
        ? new Date(doc.createdAt).toISOString()
        : doc.updatedAt
          ? new Date(doc.updatedAt).toISOString()
          : null,
      planName: doc.planName ?? doc.plan ?? 'Pro Plan',
      interval: doc.interval ?? (doc.billing === 'yearly' ? 'year' : 'month'),
      amount: doc.amount ?? 0,
      currency: String(doc.currency ?? 'USD').toUpperCase(),
      status: statusMap[doc.status] ?? doc.status ?? 'paid',
      transactionId: doc.transactionId ?? null,
      receiptUrl: doc.receiptUrl ?? null,
    }));

    return res.json({ data: history });
  } catch (err) {
    console.error('GET billing history error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 502 : 500);
    return res.status(status).json({ error: err?.message || 'Could not load billing history' });
  }
});

app.post('/api/billing/portal', requireSessionAuth, validate(billingPortalBodySchema), async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const db = client.db(dbName);
    const userIds = [userId];
    if (ObjectId.isValid(userId)) {
      userIds.push(new ObjectId(userId));
    }
    const userOrEmailFilter = {
      $or: [
        { userId: { $in: userIds } },
        ...(req.user.email
          ? [
              { userEmail: req.user.email },
              { customerEmail: req.user.email },
              { 'metadata.email': req.user.email },
            ]
          : []),
      ],
    };

    const latest = await db
      .collection(paymentsCollectionName)
      .findOne(userOrEmailFilter, { sort: { createdAt: -1 } });
    let stripeCustomerId = latest?.stripeCustomerId ?? null;

    if (!stripeCustomerId && req.user.email) {
      try {
        const customers = await getStripe().customers.list({
          email: req.user.email,
          limit: 1,
        });
        if (customers.data.length > 0) {
          stripeCustomerId = customers.data[0].id;
        }
      } catch (cErr) {}
    }

    if (!stripeCustomerId) {
      return res.status(400).json({
        error: 'No Stripe customer is linked to this account yet. Please choose a plan first.',
      });
    }

    const returnUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
    const session = await getStripe().billingPortal.sessions.create({
      customer: stripeCustomerId,
      return_url: `${returnUrl}/billing`,
    });

    return res.status(201).json({ data: { url: session.url } });
  } catch (err) {
    console.error('POST billing portal error:', err?.message ?? err);
    const status =
      err?.statusCode ??
      (err?.type === 'StripeInvalidRequestError' ? 400 : 502);
    return res.status(status).json({ error: err?.message || 'Could not create billing portal session' });
  }
});

app.get('/api/stats', async (_req, res) => {
  try {
    const db = client.db(dbName);
    const [jobs, seekers, recruiters] = await Promise.all([
      db.collection(jobsCollectionName).find({ isDeleted: { $ne: true } }, {
        projection: { status: 1, isActive: 1, companyName: 1, createdAt: 1 },
      }).toArray(),
      db.collection('user').find({ role: 'seeker' }, {
        projection: { _id: 1 },
      }).toArray(),
      db.collection('user').find({ role: 'recruiter' }, {
        projection: { companyName: 1 },
      }).toArray(),
    ]);

    const closedStatuses = new Set(['closed', 'expired', 'filled', 'archived']);
    const activeJobs = jobs.filter((job) => {
      const status = String(job.status ?? '').toLowerCase();
      return job.isActive !== false && !closedStatuses.has(status);
    }).length;
    const now = new Date();
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const newJobsThisMonth = jobs.filter((job) => {
      const createdAt = job.createdAt ? new Date(job.createdAt) : null;
      return createdAt && !Number.isNaN(createdAt.getTime()) && createdAt >= monthStart;
    }).length;
    const companyNames = new Set();
    for (const value of [
      ...jobs.map((job) => job.companyName),
      ...recruiters.map((user) => user.companyName),
    ]) {
      if (typeof value === 'string' && value.trim()) {
        companyNames.add(value.trim().toLocaleLowerCase());
      }
    }

    return res.json({
      data: {
        activeJobs,
        newJobsThisMonth,
        companies: companyNames.size,
        jobSeekers: seekers.length,
        satisfactionRate: null,
      },
    });
  } catch (err) {
    console.error('GET platform stats error:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not load platform statistics' });
  }
});

function normalizeTypeKey(type) {
  return String(type ?? '')
    .toLowerCase()
    .replace(/[^a-z]/g, '');
}

function companySlug(value) {
  return String(value ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/^-+|-+$/g, '');
}

function isJobOpen(job) {
  return job.isActive !== false &&
    !['closed', 'expired', 'filled', 'archived'].includes(String(job.status ?? '').toLowerCase());
}

function companyText(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function companyWebsite(value) {
  const text = companyText(value);
  if (!text) return null;
  try {
    const url = new URL(text);
    return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null;
  } catch {
    return null;
  }
}

function companyData(jobs, recruiters) {
  const companies = new Map();
  const addCompany = (name, source = {}) => {
    const companyName = typeof name === 'string' ? name.trim() : '';
    const slug = companySlug(companyName);
    if (!companyName || !slug) return null;
    const key = slug;
    const current = companies.get(key) ?? {
      slug,
      name: companyName,
      logoUrl: null,
      industry: null,
      size: null,
      website: null,
      description: null,
      locations: new Set(),
      jobs: [],
    };
    current.logoUrl ??= companyText(source.logoUrl) ?? companyText(source.companyOverview?.imageUrl);
    current.industry ??= companyText(source.companyOverview?.industry) ?? companyText(source.companyIndustry);
    current.size ??= companyText(source.companyOverview?.size) ?? companyText(source.companySize);
    current.website ??= companyWebsite(source.companyOverview?.website) ?? companyWebsite(source.website);
    current.description ??= companyText(source.companyOverview?.description) ?? companyText(source.companyDescription);
    companies.set(key, current);
    return current;
  };

  for (const recruiter of recruiters) {
    addCompany(recruiter.companyName, recruiter);
  }
  for (const job of jobs) {
    const company = addCompany(job.companyName, job);
    if (!company) continue;
    const location = typeof job.location === 'string' ? job.location.trim() : '';
    if (location) company.locations.add(location);
    const id = String(job._id ?? job.id ?? '');
    if (!id) continue;
    const createdAt = job.createdAt ? new Date(job.createdAt) : null;
    const salaryMin = job.salaryMin == null ? null : Number(job.salaryMin);
    const salaryMax = job.salaryMax == null ? null : Number(job.salaryMax);
    company.jobs.push({
      id,
      title: typeof job.title === 'string' && job.title.trim() ? job.title.trim() : 'Untitled job',
      location: location || (job.remote === true ? 'Remote' : null),
      type: typeof job.type === 'string' ? job.type : null,
      remote: job.remote === true,
      salaryMin: salaryMin !== null && Number.isFinite(salaryMin) ? salaryMin : null,
      salaryMax: salaryMax !== null && Number.isFinite(salaryMax) ? salaryMax : null,
      currency: typeof job.currency === 'string' ? job.currency : null,
      salaryFrequency: typeof job.salaryFrequency === 'string' ? job.salaryFrequency : null,
      status: isJobOpen(job) ? 'open' : 'closed',
      createdAt: createdAt && !Number.isNaN(createdAt.getTime()) ? createdAt.toISOString() : null,
    });
  }

  return [...companies.values()].map((company) => {
    company.jobs.sort((a, b) => new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime());
    const { jobs: companyJobs, locations, ...details } = company;
    return {
      ...details,
      locations: [...locations].sort((a, b) => a.localeCompare(b)),
      jobs: companyJobs,
      jobCount: companyJobs.length,
      openJobCount: companyJobs.filter((job) => job.status === 'open').length,
    };
  });
}

app.get('/api/companies', async (_req, res) => {
  try {
    const db = client.db(dbName);
    const [jobs, recruiters] = await Promise.all([
      db.collection(jobsCollectionName)
        .find({ isDeleted: { $ne: true } })
        .toArray(),
      db.collection('user')
        .find(
          { role: 'recruiter', companyName: { $type: 'string', $ne: '' } },
          { projection: { companyName: 1, companyIndustry: 1, companySize: 1, website: 1, companyDescription: 1 } },
        )
        .toArray(),
    ]);
    const companies = companyData(jobs, recruiters)
      .map(({ jobs: _jobs, ...company }) => company)
      .sort((a, b) => a.name.localeCompare(b.name));
    return res.json({ data: companies });
  } catch (err) {
    console.error('GET companies error:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not load companies' });
  }
});

app.get('/api/companies/:slug', validate(companySlugParamSchema), async (req, res) => {
  try {
    const slug = req.params.slug;
    const db = client.db(dbName);
    const [jobs, recruiters] = await Promise.all([
      db.collection(jobsCollectionName)
        .find({ isDeleted: { $ne: true } })
        .toArray(),
      db.collection('user')
        .find(
          { role: 'recruiter', companyName: { $type: 'string', $ne: '' } },
          { projection: { companyName: 1, companyIndustry: 1, companySize: 1, website: 1, companyDescription: 1 } },
        )
        .toArray(),
    ]);
    const company = companyData(jobs, recruiters).find((item) => item.slug === slug);
    if (!company) return res.status(404).json({ error: 'Company not found' });
    const { jobs: companyJobs, locations, ...details } = company;
    return res.json({
      data: {
        company: {
          ...details,
          locations: [...locations].sort((a, b) => a.localeCompare(b)),
          jobCount: companyJobs.length,
          openJobCount: companyJobs.filter((job) => job.status === 'open').length,
        },
        jobs: companyJobs,
      },
    });
  } catch (err) {
    console.error('GET company details error:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not load company details' });
  }
});

function toJob(doc) {
  if (!doc) return null;
  const job = { ...doc };
  job.id = String(job._id ?? job.id ?? '');
  delete job._id;
  delete job.recruiterId;
  delete job.isSeed;
  job.salaryMin = job.salaryMin == null ? null : Number(job.salaryMin);
  job.salaryMax = job.salaryMax == null ? null : Number(job.salaryMax);
  job.easyApply = job.easyApply === true;
  job.hot = job.hot === true;
  job.remote = job.remote === true;
  job.verifiedEmployer = job.verifiedEmployer === true;
  return job;
}

function toJobDetail(doc, isOwner, hasApplied, isSaved) {
  if (!doc) return null;
  const job = { ...doc };
  job.id = String(job._id ?? job.id ?? '');
  delete job._id;
  delete job.recruiterId;
  delete job.isSeed;

  job.salaryMin = job.salaryMin == null ? null : Number(job.salaryMin);
  job.salaryMax = job.salaryMax == null ? null : Number(job.salaryMax);
  job.easyApply = job.easyApply === true;
  job.hot = job.hot === true;
  job.remote = job.remote === true;
  job.verifiedEmployer = job.verifiedEmployer === true;
  job.responsibilities = Array.isArray(job.responsibilities) ? job.responsibilities : [];
  job.requirements = Array.isArray(job.requirements) ? job.requirements : [];
  job.skills = Array.isArray(job.skills) ? job.skills : [];
  job.benefits = Array.isArray(job.benefits) ? job.benefits : [];
  job.companyOverview = job.companyOverview ?? null;
  job.status = job.status ?? 'open';
  job.createdAt = job.createdAt ? new Date(job.createdAt).toISOString() : null;

  job.isOwner = isOwner;
  job.hasApplied = hasApplied;
  job.isSaved = isSaved;

  return job;
}

app.get('/api/dashboard', requireSessionAuth, async (req, res) => {
  try {
    const db = client.db(dbName);
    const userId = String(req.user._id ?? req.user.id);

    let savedJobsCount = 0;
    let applicationsCount = 0;
    let interviewsCount = 0;
    let offersCount = 0;

    const realSaved = await db.collection(savedJobsCollectionName).countDocuments({
      $or: [
        { userId },
        ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : []),
      ],
    });
    const realApplied = await db.collection(applicationsCollectionName).countDocuments({
      $or: [
        { userId },
        ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : []),
      ],
    });
    savedJobsCount = realSaved;
    applicationsCount = realApplied;

    const recentActivity = [
      {
        id: "act-1",
        type: "status_update",
        title: "Application for Senior Product Designer at TechFlow updated to 'Under Review'",
        highlight: "'Under Review'",
        timeAgo: "2 hours ago",
      },
      {
        id: "act-2",
        type: "job_alert",
        title: "New Job Alert: Lead Frontend Engineer at FinGrid matches your profile.",
        timeAgo: "5 hours ago",
      },
      {
        id: "act-3",
        type: "message",
        title: "You have a new message from Sarah Jenkins (Hiring Manager at CloudOps).",
        timeAgo: "1 day ago",
      },
      {
        id: "act-4",
        type: "status_update",
        title: "Application for Senior Product Designer at TechFlow updated to 'Under Review'",
        highlight: "'Under Review'",
        timeAgo: "2 hours ago",
      },
      {
        id: "act-5",
        type: "job_alert",
        title: "New Job Alert: Lead Frontend Engineer at FinGrid matches your profile.",
        timeAgo: "5 hours ago",
      },
      {
        id: "act-6",
        type: "message",
        title: "You have a new message from Sarah Jenkins (Hiring Manager at CloudOps).",
        timeAgo: "1 day ago",
      },
    ];

    res.json({
      data: {
        stats: {
          savedJobs: savedJobsCount,
          applications: applicationsCount,
          interviews: interviewsCount,
          offers: offersCount,
        },
        recentActivity,
      },
    });
  } catch (err) {
    console.error('GET dashboard error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const handleGetJobs = async (req, res) => {
  try {
    const { q, status, type, workMode, level, salaryMin, sort, page, limit } = req.query;

    const db = client.db(dbName);
    const jobs = await db.collection(jobsCollectionName)
      .find({ isDeleted: { $ne: true } })
      .toArray();

    const searched = q
      ? jobs.filter((job) => {
          const haystack = `${job.title ?? ''} ${job.companyName ?? ''} ${job.location ?? ''}`.toLowerCase();
          return haystack.includes(q.toLowerCase());
        })
      : jobs;

    const typeCounts = {};
    for (const job of searched) {
      const key = normalizeTypeKey(job.type);
      typeCounts[key] = (typeCounts[key] ?? 0) + 1;
    }

    const filtered = searched.filter((job) => {
      if (status === 'open') {
        const jobStatus = String(job.status ?? '').toLowerCase();
        if (
          job.isActive === false ||
          ['closed', 'expired', 'filled', 'archived'].includes(jobStatus)
        ) {
          return false;
        }
      } else if (status === 'closed') {
        const jobStatus = String(job.status ?? '').toLowerCase();
        if (
          job.isActive !== false &&
          !['closed', 'expired', 'filled', 'archived'].includes(jobStatus)
        ) {
          return false;
        }
      }
      if (type) {
        const types = String(type).split(',').map(t => t.trim()).filter(Boolean);
        const matchesType = types.some(
          (t) => String(job.type ?? '').toLowerCase() === t.toLowerCase(),
        );
        if (!matchesType) return false;
      }
      if (workMode && String(job.workMode ?? '').toLowerCase() !== workMode.toLowerCase()) {
        return false;
      }
      if (level && String(job.level ?? '').toLowerCase() !== level.toLowerCase()) {
        return false;
      }
      if (salaryMin) {
        const minSalary = Number(salaryMin);
        if (Number(job.salaryMax ?? 0) < minSalary) return false;
      }
      return true;
    });

    const sorted = [...filtered].sort((a, b) => {
      if (sort === 'salary') {
        const aVal = Number(a.salaryMax ?? a.salaryMin ?? 0);
        const bVal = Number(b.salaryMax ?? b.salaryMin ?? 0);
        return bVal - aVal;
      }
      const aTime = new Date(a.createdAt ?? 0).getTime();
      const bTime = new Date(b.createdAt ?? 0).getTime();
      return bTime - aTime;
    });

    const total = sorted.length;
    const totalPages = Math.ceil(total / limit);
    const start = (page - 1) * limit;
    const data = sorted.slice(start, start + limit).map(toJob);

    res.json({
      data,
      meta: {
        page,
        limit,
        total,
        totalPages: totalPages > 0 ? totalPages : 0,
        facets: { type: typeCounts },
      },
    });
  } catch (err) {
    console.error('GET jobs error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.get('/api/jobs', validate(jobFiltersQuerySchema), handleGetJobs);

const handleCreateJob = async (req, res) => {
  try {
    const role = String(req.user.role ?? '').toLowerCase();
    if (role !== 'recruiter' && role !== 'admin') {
      return res.status(403).json({ error: 'Only recruiters can publish jobs' });
    }

    const input = req.body;
    const title = input.title;
    const companyName = input.companyName;
    const description = input.description;
    const location = input.location;

    const parseList = (value, field) => {
      if (value == null || value === '') return [];
      if (!Array.isArray(value)) {
        throw new Error(`${field} must be an array of strings`);
      }
      if (!value.every((item) => typeof item === 'string')) {
        throw new Error(`${field} must be a list of strings`);
      }
      return value.map((item) => item.trim()).filter(Boolean);
    };

    const parseSalary = (value, field) => {
      if (value == null || value === '') return null;
      const salary = Number(value);
      if (!Number.isFinite(salary) || salary < 0) {
        throw new Error(`${field} must be a non-negative number`);
      }
      return salary;
    };

    let salaryMin;
    let salaryMax;
    let responsibilities;
    let requirements;
    let skills;
    let benefits;
    let applicationDeadline = null;
    try {
      salaryMin = parseSalary(input.salaryMin, 'salaryMin');
      salaryMax = parseSalary(input.salaryMax, 'salaryMax');
      responsibilities = parseList(input.responsibilities, 'responsibilities');
      requirements = parseList(input.requirements, 'requirements');
      skills = parseList(input.skills, 'skills');
      benefits = parseList(input.benefits, 'benefits');
      if (input.applicationDeadline) {
        applicationDeadline = new Date(input.applicationDeadline);
        if (Number.isNaN(applicationDeadline.getTime())) {
          throw new Error('applicationDeadline must be a valid date');
        }
      }
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }

    if (salaryMin != null && salaryMax != null && salaryMax < salaryMin) {
      return res.status(400).json({ error: 'salaryMax must be greater than or equal to salaryMin' });
    }

    const userId = String(req.user._id ?? req.user.id ?? '');
    if (!userId) {
      return res.status(401).json({ error: 'Authenticated user id is missing' });
    }

    const job = {
      title,
      companyName,
      description,
      location,
      responsibilities,
      requirements,
      skills,
      benefits,
      type: input.type ?? 'Full-time',
      workMode: input.workMode ?? (input.remote ? 'Remote' : ''),
      level: input.level ?? '',
      salaryMin,
      salaryMax,
      currency: input.currency ?? 'USD',
      salaryFrequency: input.salaryFrequency ?? '',
      applicationDeadline,
      companyOverview: input.companyOverview ?? null,
      logoUrl: input.logoUrl ?? null,
      remote: input.remote === true || String(input.workMode ?? '').toLowerCase() === 'remote',
      easyApply: input.easyApply === true,
      hot: false,
      verifiedEmployer: false,
      status: 'open',
      recruiterId: userId,
      applicantsCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
      isSeed: false,
    };

    const result = await client.db(dbName).collection(jobsCollectionName).insertOne(job);
    res.status(201).json({
      success: true,
      message: 'Job published successfully',
      data: toJob({ ...job, _id: result.insertedId }),
    });
  } catch (err) {
    console.error('POST create job error:', err?.message ?? err);
    res.status(500).json({ error: 'Could not publish job' });
  }
};

app.post('/api/jobs', requireSessionAuth, requireRole('recruiter', 'admin'), validate(createJobBodySchema), handleCreateJob);
app.post('/jobs', requireSessionAuth, requireRole('recruiter', 'admin'), validate(createJobBodySchema), handleCreateJob);

const handleGetJobById = async (req, res) => {
  try {
    const { id } = req.params;
    const db = client.db(dbName);
    const doc = await db.collection(jobsCollectionName).findOne({
      _id: new ObjectId(id),
      isDeleted: { $ne: true },
    });
    if (!doc) {
      return res.status(404).json({ error: 'Job not found' });
    }

    const userIdStr = req.user ? String(req.user._id ?? req.user.id) : null;
    let hasApplied = false;
    let isSaved = false;

    if (userIdStr) {
      const appDoc = await db.collection(applicationsCollectionName).findOne({
        jobId: id,
        $or: [
          { userId: userIdStr },
          ...(ObjectId.isValid(userIdStr) ? [{ userId: new ObjectId(userIdStr) }] : []),
        ],
      });
      hasApplied = !!appDoc;

      const saveDoc = await db.collection(savedJobsCollectionName).findOne({
        jobId: id,
        $or: [
          { userId: userIdStr },
          ...(ObjectId.isValid(userIdStr) ? [{ userId: new ObjectId(userIdStr) }] : []),
        ],
      });
      isSaved = !!saveDoc;
    }

    const isOwner = !!(
      req.user &&
      doc.recruiterId &&
      String(doc.recruiterId) === userIdStr
    );

    const job = toJobDetail(doc, isOwner, hasApplied, isSaved);
    res.json({ data: job });
  } catch (err) {
    console.error('GET job details error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.get('/api/jobs/:id', validate(objectIdParamSchema), optionalSessionAuth, handleGetJobById);

const handleApplyToJob = async (req, res) => {
  try {
    const jobId = req.params.id;

    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const role = req.user.role ?? 'seeker';
    if (role === 'recruiter' || role === 'admin') {
      return res.status(403).json({ error: 'Only job seekers can apply' });
    }

    const db = client.db(dbName);
    const job = await db.collection(jobsCollectionName).findOne({
      _id: new ObjectId(jobId),
      isDeleted: { $ne: true },
    });
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    if (job.status && job.status !== 'open') {
      return res.status(400).json({ error: 'Job closed' });
    }

    const userIdStr = String(req.user._id ?? req.user.id);
    const existing = await db.collection(applicationsCollectionName).findOne({
      jobId,
      $or: [
        { userId: userIdStr },
        ...(ObjectId.isValid(userIdStr) ? [{ userId: new ObjectId(userIdStr) }] : []),
        { seekerId: userIdStr },
        ...(ObjectId.isValid(userIdStr) ? [{ seekerId: new ObjectId(userIdStr) }] : []),
      ],
    });

    if (existing) {
      return res.status(409).json({ error: 'Already applied for this job', hasApplied: true });
    }

    const userIdStrForPlan = String(req.user._id ?? req.user.id);
    const planFilter = {
      $or: [
        { userId: userIdStrForPlan },
        ...(ObjectId.isValid(userIdStrForPlan) ? [{ userId: new ObjectId(userIdStrForPlan) }] : []),
        ...(req.user.email
          ? [
              { userEmail: req.user.email },
              { customerEmail: req.user.email },
              { 'metadata.email': req.user.email },
            ]
          : []),
      ],
      status: { $in: ['success', 'paid'] },
    };
    const latestPaymentForLimit = await db
      .collection(paymentsCollectionName)
      .findOne(planFilter, { sort: { createdAt: -1 } });
    const paidPlan =
      latestPaymentForLimit && latestPaymentForLimit.plan && latestPaymentForLimit.plan !== 'starter'
        ? String(latestPaymentForLimit.plan).toLowerCase()
        : 'starter';

    if (paidPlan === 'starter') {
      const applicationCount = await db
        .collection(applicationsCollectionName)
        .countDocuments({
          $or: [
            { userId: userIdStrForPlan },
            ...(ObjectId.isValid(userIdStrForPlan) ? [{ userId: new ObjectId(userIdStrForPlan) }] : []),
            { seekerId: userIdStrForPlan },
            ...(ObjectId.isValid(userIdStrForPlan) ? [{ seekerId: new ObjectId(userIdStrForPlan) }] : []),
          ],
        });
      if (applicationCount >= FREE_PLAN_APPLICATION_LIMIT) {
        return res.status(402).json({
          error: `Free plan allows ${FREE_PLAN_APPLICATION_LIMIT} applications. Upgrade to a paid plan to apply for more jobs.`,
          limitReached: true,
          limit: FREE_PLAN_APPLICATION_LIMIT,
          currentPlan: paidPlan,
        });
      }
    }

    await db.collection(applicationsCollectionName).insertOne({
      jobId,
      userId: userIdStr,
      seekerId: userIdStr,
      recruiterId: job.recruiterId ?? null,
      jobTitle: job.title ?? null,
      companyName: job.companyName ?? null,
      logoUrl: job.logoUrl ?? null,
      status: 'applied',
      coverNote: null,
      resumeUrl: null,
      appliedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await db.collection(jobsCollectionName).updateOne(
      { _id: new ObjectId(jobId) },
      { $inc: { applicantsCount: 1 } },
    );

    res.status(200).json({ success: true, message: 'Application submitted', hasApplied: true });
  } catch (err) {
    console.error('POST apply error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.post('/api/jobs/:id/apply', requireSessionAuth, requireRole('seeker'), validate(objectIdParamSchema), validate(applyJobBodySchema), handleApplyToJob);

const applicationStatuses = new Set([
  'applied',
  'new',
  'reviewing',
  'under_review',
  'shortlisted',
  'interview',
  'scheduled',
  'rejected',
  'hired',
  'withdrawn',
]);

app.patch('/api/applications/:id/status', requireSessionAuth, requireRole('recruiter', 'admin'), validate(objectIdParamSchema), validate(applicationStatusBodySchema), async (req, res) => {
  try {
    const status = req.body.status;

    const user = req.user;
    const role = String(user.role ?? '').toLowerCase();

    const db = client.db(dbName);
    const applications = db.collection(applicationsCollectionName);
    const application = await applications.findOne({ _id: new ObjectId(req.params.id) });
    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    if (role !== 'admin') {
      const userId = String(user._id ?? user.id);
      let recruiterId = application.recruiterId == null ? '' : String(application.recruiterId);

      if (!recruiterId && application.jobId) {
        const jobId = String(application.jobId);
        const jobQuery = ObjectId.isValid(jobId)
          ? { _id: new ObjectId(jobId) }
          : { id: jobId };
        const job = await db.collection(jobsCollectionName).findOne(jobQuery, {
          projection: { recruiterId: 1 },
        });
        recruiterId = job?.recruiterId == null ? '' : String(job.recruiterId);
      }

      if (!recruiterId || recruiterId !== userId) {
        return res.status(403).json({ error: 'You cannot update this application' });
      }
    }

    const updatedAt = new Date();
    await applications.updateOne(
      { _id: application._id },
      { $set: { status, updatedAt } },
    );

    return res.json({
      success: true,
      data: {
        id: String(application._id),
        status,
        updatedAt: updatedAt.toISOString(),
      },
    });
  } catch (err) {
    console.error('PATCH application status error:', err?.message ?? err);
    return res.status(500).json({ error: 'Could not update application status' });
  }
});

const handleGetSavedJobs = async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);

    const docs = await client
      .db(dbName)
      .collection(savedJobsCollectionName)
      .find({
        $or: [
          { userId },
          ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : []),
        ],
      })
      .toArray();

    const ids = docs
      .map((doc) => String(doc.jobId ?? ''))
      .filter(Boolean);
    res.json({ data: ids });
  } catch (err) {
    console.error('GET saved-jobs error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.get('/api/saved-jobs', requireSessionAuth, handleGetSavedJobs);

const handleSaveJob = async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const jobId = req.params.id;
    const db = client.db(dbName);
    await db
      .collection(savedJobsCollectionName)
      .updateOne(
        { userId, jobId },
        { $set: { userId, jobId, savedAt: new Date() } },
        { upsert: true },
      );
    res.json({ saved: true });
  } catch (err) {
    console.error('POST save error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.post('/api/jobs/:id/save', requireSessionAuth, requireRole('seeker'), validate(objectIdParamSchema), validate(saveJobBodySchema), handleSaveJob);

const handleDeleteSavedJob = async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const jobId = req.params.id;
    const db = client.db(dbName);
    await db
      .collection(savedJobsCollectionName)
      .deleteOne({ userId, jobId });
    res.json({ saved: false });
  } catch (err) {
    console.error('DELETE save error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.delete('/api/jobs/:id/save', requireSessionAuth, requireRole('seeker'), validate(objectIdParamSchema), handleDeleteSavedJob);

const handleGetMyJobIds = async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const docs = await client
      .db(dbName)
      .collection(applicationsCollectionName)
      .find({
        $or: [
          { userId },
          ...(ObjectId.isValid(userId) ? [{ userId: new ObjectId(userId) }] : []),
          { seekerId: userId },
          ...(ObjectId.isValid(userId) ? [{ seekerId: new ObjectId(userId) }] : []),
        ],
      })
      .project({ jobId: 1 })
      .toArray();

    const jobIds = docs.map((doc) => String(doc.jobId)).filter(Boolean);
    res.json({ data: jobIds });
  } catch (err) {
    console.error('GET my-job-ids error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.get('/api/applications/my-job-ids', requireSessionAuth, handleGetMyJobIds);

const handleTrackActivity = async (req, res) => {
  try {
    const userId = String(req.user._id ?? req.user.id);
    const { event, jobId, metadata } = req.body;

    const doc = {
      userId,
      event,
      jobId: jobId || null,
      metadata: metadata ?? null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await client.db(dbName).collection(activitiesCollectionName).insertOne(doc);
    res.json({ ok: true, id: String(result.insertedId) });
  } catch (err) {
    console.error('POST activity/track error:', err?.message ?? err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.post('/api/activity/track', requireSessionAuth, validate(activityTrackBodySchema), handleTrackActivity);

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err?.message ?? err);
  const isProduction = process.env.NODE_ENV === 'production';
  res.status(500).json({
    error: 'Internal server error',
    ...(isProduction ? {} : { message: err?.message, stack: err?.stack }),
  });
});

async function run() {
  try {
    await client.connect();
    await client.db('admin').command({ ping: 1 });
    console.log('MongoDB connection successful');
  } catch (err) {
    console.error('MongoDB connection failed:', err.message);
  }
}

if (require.main === module && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
  run();
}

module.exports = app;