'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Check } from 'lucide-react';
import { loadCheckout, postJson } from '@/components/billing/RazorpayCheckoutButton';
import {
  AUTHORITY_PLANS,
  formatAuthorityPrice,
  type AuthorityPeriod,
  type AuthorityPlanId,
} from '@/lib/billing/authority-plans';

/**
 * Mastyf Authority pricing with Razorpay Checkout (same account and verify step as the rest of mastyf.ai).
 * Prepaid periods, no auto-renewal: the server records the paid period; we contact the buyer to set up.
 */

type OrderResponse = {
  orderId: string;
  amount: number;
  currency: string;
  keyId: string;
  plan: { id: AuthorityPlanId; name: string; period: AuthorityPeriod };
  prefill: { name: string; email: string };
};
type Status = { kind: 'idle' | 'opening' | 'verifying' | 'cancelled' } | { kind: 'error'; message: string } |
  { kind: 'paid'; plan: string };

const TIERS: {
  id: 'open' | AuthorityPlanId | 'enterprise';
  name: string;
  who: string;
  features: string[];
  highlight?: boolean;
}[] = [
  {
    id: 'open',
    name: 'Open source',
    who: 'Run it yourself',
    features: [
      'Decision engine, signed single-use grants',
      'Key vault with daily limits (Rust)',
      'Two-person approval, passkeys, undo windows',
      'AI-agent limits and the break-it sandbox',
      'Train your own risk model',
    ],
  },
  {
    id: 'team',
    name: 'Team',
    who: 'Up to 50 people',
    highlight: true,
    features: [
      'Everything in open source',
      'Log connectors: GitHub, Okta, AWS CloudTrail',
      'Shadow-mode pilot on your real logs',
      'Production risk model, ask-once approvals',
      'SCIM sync from Okta or Entra ID',
      'Setup call and email support',
    ],
  },
  {
    id: 'business',
    name: 'Business',
    who: 'Up to 250 people',
    features: [
      'Everything in Team',
      'Insider-detection pack (179 of 187 on CMU CERT)',
      'Leak tracing on every copy that leaves',
      'Vendor-side script firewall',
      'Managed hosting on request',
      'Priority support, audit evidence packs',
    ],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    who: 'Any size, your terms',
    features: [
      'Commercial licence (no AGPL obligations)',
      'High availability across zones',
      'On-premises or your own cloud',
      'Response-time SLA and named engineer',
      'Penetration-test and procurement support',
    ],
  },
];

export function AuthorityPricing({ signedIn }: { signedIn: boolean }) {
  const router = useRouter();
  const [period, setPeriod] = useState<'monthly' | 'yearly'>('monthly');
  const [busy, setBusy] = useState<AuthorityPlanId | null>(null);
  const [status, setStatus] = useState<Status>({ kind: 'idle' });

  async function buy(plan: AuthorityPlanId, p: AuthorityPeriod) {
    if (!signedIn) {
      router.push(`/login?callbackUrl=${encodeURIComponent('/authority#pricing')}`);
      return;
    }
    setBusy(plan);
    setStatus({ kind: 'opening' });
    try {
      const [order] = await Promise.all([
        postJson<OrderResponse>('/api/authority/checkout', { plan, period: p }),
        loadCheckout(),
      ]);
      if (!window.Razorpay) throw new Error('Razorpay Checkout did not load. Try again.');
      const checkout = new window.Razorpay({
        key: order.keyId,
        order_id: order.orderId,
        amount: order.amount,
        currency: order.currency,
        name: 'Mastyf',
        description: `${order.plan.name}${p === 'once' ? '' : p === 'yearly' ? ', 1 year' : ', 30 days'}`,
        prefill: order.prefill,
        notes: { product: 'mastyf-authority' },
        theme: { color: '#b5832a' },
        handler: async (r: { razorpay_payment_id: string; razorpay_order_id: string; razorpay_signature: string }) => {
          setStatus({ kind: 'verifying' });
          try {
            await postJson('/api/billing/verify-payment', r);
            setStatus({ kind: 'paid', plan: order.plan.name });
          } catch (e) {
            setStatus({ kind: 'error', message: e instanceof Error ? e.message : 'Could not confirm the payment.' });
          } finally {
            setBusy(null);
          }
        },
        modal: { ondismiss: () => { setBusy(null); setStatus((s) => (s.kind === 'opening' ? { kind: 'cancelled' } : s)); } },
      });
      checkout.on('payment.failed', (r) => {
        setBusy(null);
        setStatus({ kind: 'error', message: r.error?.description || 'The payment failed. Try again or use another method.' });
      });
      checkout.open();
    } catch (e) {
      setBusy(null);
      setStatus({ kind: 'error', message: e instanceof Error ? e.message : 'Something went wrong. Try again.' });
    }
  }

  const yearlySaving = (plan: AuthorityPlanId) => {
    const a = AUTHORITY_PLANS[plan].amounts;
    return a.monthly && a.yearly ? Math.round(100 - (100 * a.yearly) / (12 * a.monthly)) : 0;
  };

  return (
    <div className="ap">
      <div className="ap__toggle" role="radiogroup" aria-label="Billing period">
        {(['monthly', 'yearly'] as const).map((p) => (
          <button key={p} type="button" role="radio" aria-checked={period === p} onClick={() => setPeriod(p)}>
            {p === 'monthly' ? 'Monthly' : `Yearly · save ${yearlySaving('team')}%`}
          </button>
        ))}
      </div>

      <div className="ap__grid">
        {TIERS.map((t) => (
          <article key={t.id} className={`ap__card${t.highlight ? ' ap__card--hi' : ''}`}>
            {t.highlight ? <p className="ap__badge">Most teams start here</p> : null}
            <h3>{t.name}</h3>
            <p className="ap__who">{t.who}</p>
            <p className="ap__price">
              {t.id === 'open' ? (
                <><strong>Free</strong><span>AGPL-3.0</span></>
              ) : t.id === 'enterprise' ? (
                <><strong>Custom</strong><span>annual contract</span></>
              ) : (
                <>
                  <strong>{formatAuthorityPrice(t.id, period)}</strong>
                  <span>{period === 'monthly' ? '/ month' : '/ year'}</span>
                </>
              )}
            </p>
            <ul>
              {t.features.map((f) => (
                <li key={f}><Check size={15} strokeWidth={2} aria-hidden="true" /><span>{f}</span></li>
              ))}
            </ul>
            <div className="ap__cta">
              {t.id === 'open' ? (
                <a className="btn" href="https://github.com/mastyf-ai/mastyf-authority" target="_blank" rel="noopener noreferrer">
                  Get it on GitHub
                </a>
              ) : t.id === 'enterprise' ? (
                <Link className="btn" href="/pilot">Talk to us</Link>
              ) : (
                <button
                  type="button"
                  className={`btn${t.highlight ? ' btn-primary' : ''}`}
                  disabled={busy !== null}
                  aria-busy={busy === t.id}
                  onClick={() => buy(t.id as AuthorityPlanId, period)}
                >
                  {busy === t.id ? (status.kind === 'verifying' ? 'Confirming…' : 'Opening checkout…') : `Buy ${t.name}`}
                </button>
              )}
            </div>
          </article>
        ))}
      </div>

      <div className="ap__report">
        <div>
          <strong>Damage Ceiling Report</strong>
          <span>
            Free for our first 10 companies. Skip the queue with a priority report, delivered in 48 hours:{' '}
            {formatAuthorityPrice('report', 'once')} one-time.
          </span>
        </div>
        <div className="ap__report-cta">
          <a className="btn" href="#report">Request free report</a>
          <button type="button" className="btn" disabled={busy !== null} onClick={() => buy('report', 'once')}>
            {busy === 'report' ? 'Opening checkout…' : 'Buy priority report'}
          </button>
        </div>
      </div>

      {status.kind === 'cancelled' ? <p className="notice" role="status">Payment cancelled. Nothing was charged.</p> : null}
      {status.kind === 'error' ? <p className="notice notice--error" role="alert">{status.message}</p> : null}
      {status.kind === 'paid' ? (
        <p className="notice notice--ok" role="status">
          <strong>Payment received for {status.plan}.</strong> We&apos;ll email you within one business day to set up
          connectors and your shadow-mode pilot. Your receipt comes from Razorpay.
        </p>
      ) : null}

      <p className="ap__fine">
        Prices in Indian rupees. Prepaid for the period you choose, with no auto-renewal. Research preview: paid plans
        start in shadow mode, so nothing is blocked until you switch enforcement on together with us.
      </p>
    </div>
  );
}
