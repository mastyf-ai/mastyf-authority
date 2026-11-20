'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Check } from 'lucide-react';
import { loadCheckout, postJson, RazorpayCheckoutButton } from '@/components/billing/RazorpayCheckoutButton';
import { PRICING_TIERS } from '@/components/landing/stats';
import { formatAuthorityPrice } from '@/lib/billing/authority-plans';
import { formatPlanPrice, isPaidPlanId, type BillingPeriod } from '@/lib/billing/plans';

/**
 * The same plans as mastyf.ai/pricing (one licence covers Shield and Authority), shown for security
 * teams: Community, Team, Business, Scale, Enterprise. The one-time Damage Ceiling Report keeps its own
 * checkout. Plans are prepaid with no auto-renewal.
 */

const SHOWN = ['community', 'team', 'business', 'scale', 'custom'] as const;

type ReportOrder = { orderId: string; amount: number; currency: string; keyId: string;
  plan: { name: string }; prefill: { name: string; email: string } };
type ReportStatus = { kind: 'idle' | 'opening' | 'verifying' | 'cancelled' | 'paid' } | { kind: 'error'; message: string };

export function AuthorityPricing({ signedIn }: { signedIn: boolean }) {
  const router = useRouter();
  const [period, setPeriod] = useState<BillingPeriod>('monthly');
  const [report, setReport] = useState<ReportStatus>({ kind: 'idle' });
  const tiers = PRICING_TIERS.filter((t) => (SHOWN as readonly string[]).includes(t.id));

  async function buyReport() {
    if (!signedIn) {
      router.push(`/login?callbackUrl=${encodeURIComponent('/authority#pricing')}`);
      return;
    }
    setReport({ kind: 'opening' });
    try {
      const [order] = await Promise.all([
        postJson<ReportOrder>('/api/authority/checkout', { plan: 'report', period: 'once' }),
        loadCheckout(),
      ]);
      if (!window.Razorpay) throw new Error('Razorpay Checkout did not load. Try again.');
      const checkout = new window.Razorpay({
        key: order.keyId, order_id: order.orderId, amount: order.amount, currency: order.currency,
        name: 'Mastyf', description: order.plan.name, prefill: order.prefill, theme: { color: '#b5832a' },
        handler: async (r: Record<string, string>) => {
          setReport({ kind: 'verifying' });
          try {
            await postJson('/api/billing/verify-payment', r);
            setReport({ kind: 'paid' });
          } catch (e) {
            setReport({ kind: 'error', message: e instanceof Error ? e.message : 'Could not confirm the payment.' });
          }
        },
        modal: { ondismiss: () => setReport((s) => (s.kind === 'opening' ? { kind: 'cancelled' } : s)) },
      });
      checkout.on('payment.failed', (r) =>
        setReport({ kind: 'error', message: r.error?.description || 'The payment failed. Try again.' }));
      checkout.open();
    } catch (e) {
      setReport({ kind: 'error', message: e instanceof Error ? e.message : 'Something went wrong. Try again.' });
    }
  }

  return (
    <div className="ap">
      <div className="ap__toggle" role="radiogroup" aria-label="Billing period">
        {(['monthly', 'yearly'] as const).map((p) => (
          <button key={p} type="button" role="radio" aria-checked={period === p} onClick={() => setPeriod(p)}>
            {p === 'monthly' ? 'Monthly' : 'Yearly · 2 months free'}
          </button>
        ))}
      </div>

      <div className="ap__grid ap__grid--five">
        {tiers.map((t) => {
          const paid = isPaidPlanId(t.id);
          return (
            <article key={t.id} className={`ap__card${t.featured ? ' ap__card--hi' : ''}`}>
              {t.featured ? <p className="ap__badge">Best for most companies</p> : null}
              <h3>{t.name}</h3>
              <p className="ap__who">{t.audience}</p>
              <p className="ap__price">
                <strong>{paid ? formatPlanPrice(t.id, period) : t.price}</strong>
                <span>{paid ? (period === 'monthly' ? '/ month' : '/ year') : t.id === 'community' ? 'AGPL-3.0' : 'annual contract'}</span>
              </p>
              <ul>
                {t.bullets.map((b) => (
                  <li key={b}><Check size={15} strokeWidth={2} aria-hidden="true" /><span>{b}</span></li>
                ))}
              </ul>
              <div className="ap__cta">
                {paid ? (
                  <RazorpayCheckoutButton
                    plan={t.id}
                    period={period}
                    label={signedIn ? `Buy ${t.name}` : 'Sign in to buy'}
                    signedIn={signedIn}
                    className={`btn${t.featured ? ' btn-primary' : ''}`}
                  />
                ) : t.id === 'community' ? (
                  <a className="btn" href="https://github.com/mastyf-ai/mastyf-authority" target="_blank" rel="noopener noreferrer">
                    Get it on GitHub
                  </a>
                ) : (
                  <Link className="btn" href="/pilot">Talk to us</Link>
                )}
              </div>
            </article>
          );
        })}
      </div>

      <div className="ap__report">
        <div>
          <strong>Damage Ceiling Report</strong>
          <span>
            Free for our first 10 companies (included with Business and Scale). Skip the queue with a priority report,
            delivered in 48 hours: {formatAuthorityPrice('report', 'once')} one-time.
          </span>
        </div>
        <div className="ap__report-cta">
          <a className="btn" href="#report">Request free report</a>
          <button type="button" className="btn" disabled={report.kind === 'opening' || report.kind === 'verifying'} onClick={buyReport}>
            {report.kind === 'opening' ? 'Opening checkout…' : report.kind === 'verifying' ? 'Confirming…' : 'Buy priority report'}
          </button>
        </div>
      </div>
      {report.kind === 'cancelled' ? <p className="notice" role="status">Payment cancelled. Nothing was charged.</p> : null}
      {report.kind === 'error' ? <p className="notice notice--error" role="alert">{report.message}</p> : null}
      {report.kind === 'paid' ? (
        <p className="notice notice--ok" role="status">
          <strong>Payment received.</strong> Check your email for how to send your logs; the report arrives within 48 hours.
        </p>
      ) : null}

      <p className="ap__fine">
        One licence covers Mastyf Shield and Mastyf Authority; the same plans are on <Link href="/pricing">mastyf.ai/pricing</Link>.
        Prices in Indian rupees, prepaid with no auto-renewal. Full refund within 7 days of a first purchase
        (<Link href="/refunds">refund policy</Link>). Research preview: Authority starts in shadow mode, so nothing is
        blocked until you switch enforcement on together with us.
      </p>
    </div>
  );
}
