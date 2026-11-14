const USD_TO_BDT = 127.6665;
const YEARLY_DISCOUNT = 0.25;
const FREE_PLAN_APPLICATION_LIMIT = 10;

const plans = [
  {
    id: 'starter',
    name: 'Starter',
    description: 'For getting started',
    icon: 'crown',
    monthlyPrice: 0,
    highlighted: false,
    features: [
      'Daily AI match brief (top 5)',
      'Verified salary bands',
      'Company insight dashboards',
      '1-click apply, unlimited',
    ],
  },
  {
    id: 'growth',
    name: 'Growth',
    description: 'Start building your insights hub:',
    icon: 'chart',
    monthlyPrice: 17,
    highlighted: true,
    features: [
      'Daily AI match brief (top 5)',
      'Verified salary bands',
      'Company insight dashboards',
      '1-click apply, unlimited',
    ],
  },
  {
    id: 'premium',
    name: 'Premium',
    description: 'For teams and power users',
    icon: 'zap',
    monthlyPrice: 99,
    highlighted: false,
    features: [
      'Everything in Pro',
      'Multi-profile career portfolios',
      'Shared talent rooms',
      'Recruiter view (read-only)',
    ],
  },
];

function round2(value) {
  return Math.round(value * 100) / 100;
}

function formatAmount(currency, amount) {
  const value = amount / 100;
  if (currency === 'USD') {
    return `$${value.toLocaleString('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`;
  }
  return `${currency} ${value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

function normalizeBilling(billing) {
  return String(billing ?? '').toLowerCase() === 'yearly' ? 'yearly' : 'monthly';
}

function getPlan(planId) {
  const id = String(planId ?? '').trim().toLowerCase();
  return plans.find((plan) => plan.id === id) ?? null;
}

function getYearlyMonthlyPrice(plan) {
  return round2(plan.monthlyPrice * (1 - YEARLY_DISCOUNT));
}

function getPlanList() {
  return plans.map((plan) => ({
    ...plan,
    yearlyMonthlyPrice: getYearlyMonthlyPrice(plan),
  }));
}

function getCheckoutPricing(plan, billing) {
  const normalized = normalizeBilling(billing);
  const months = normalized === 'yearly' ? 12 : 1;
  const perMonth =
    normalized === 'yearly' ? getYearlyMonthlyPrice(plan) : plan.monthlyPrice;
  const usdCents = Math.round(perMonth * months * 100);
  const bdtAmount = Math.round(usdCents * USD_TO_BDT);

  return {
    billing: normalized,
    interval: months === 12 ? 'year' : 'month',
    perMonth,
    usdCents,
    bdtAmount,
  };
}

module.exports = {
  YEARLY_DISCOUNT,
  USD_TO_BDT,
  FREE_PLAN_APPLICATION_LIMIT,
  formatAmount,
  getCheckoutPricing,
  getPlan,
  getPlanList,
  normalizeBilling,
};
