import React from 'react';
import { ShipStatus } from '../types';
import { CheckCircle2, AlertTriangle, XCircle, ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';

interface ShipBannerProps {
  status: ShipStatus;
  score: number;
  criticalCount: number;
  totalFindings: number;
}

export const ShipBanner: React.FC<ShipBannerProps> = ({
  status,
  score,
  criticalCount,
  totalFindings,
}) => {
  const isReady = status === 'READY TO SHIP';
  const isReview = status === 'NEEDS REVIEW';
  const isBlocked = status === 'BLOCKED';

  // Config based on status
  const config = isReady
    ? {
        border: 'border-emerald-500/40',
        bg: 'from-emerald-950/40 via-[#111827] to-[#090d16]',
        glow: 'shadow-[0_0_30px_rgba(16,185,129,0.15)]',
        badgeBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        text: 'text-emerald-400',
        icon: <ShieldCheck className="w-9 h-9 text-emerald-400" />,
        subtext: 'All shift-left security quality gates passed. Score >= 80 with zero critical vulnerabilities.',
      }
    : isReview
    ? {
        border: 'border-amber-500/40',
        bg: 'from-amber-950/40 via-[#111827] to-[#090d16]',
        glow: 'shadow-[0_0_30px_rgba(245,158,11,0.15)]',
        badgeBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        text: 'text-amber-400',
        icon: <ShieldAlert className="w-9 h-9 text-amber-400" />,
        subtext: 'Moderate security risks detected. Manual peer review required before staging deployment.',
      }
    : {
        border: 'border-rose-500/50',
        bg: 'from-rose-950/40 via-[#111827] to-[#090d16]',
        glow: 'shadow-[0_0_35px_rgba(244,63,94,0.2)]',
        badgeBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
        text: 'text-rose-400',
        icon: <ShieldX className="w-9 h-9 text-rose-400" />,
        subtext: 'High/Critical security flaws detected. Deployment gate BLOCKED to prevent production compromise.',
      };

  // Circular gauge calculations
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const scoreStrokeColor = isReady ? '#10b981' : isReview ? '#f59e0b' : '#f43f5e';

  return (
    <div
      className={`relative overflow-hidden rounded-2xl border ${config.border} bg-gradient-to-r ${config.bg} ${config.glow} p-6 md:p-8 transition-all`}
    >
      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Left: Verdict & Description */}
        <div className="flex items-start gap-5 text-center md:text-left">
          <div className="p-3.5 rounded-2xl bg-black/40 border border-slate-700/60 shadow-inner">
            {config.icon}
          </div>
          <div>
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-3">
              <span className={`text-2xl md:text-3xl font-extrabold tracking-tight ${config.text}`}>
                {status}
              </span>
              <span
                className={`text-xs uppercase font-extrabold tracking-wider px-3 py-1 rounded-full border ${config.badgeBg}`}
              >
                CI/CD Gate Status
              </span>
            </div>
            <p className="mt-2 text-sm text-slate-300 max-w-xl font-medium">{config.subtext}</p>
            <div className="mt-3 flex items-center justify-center md:justify-start gap-4 text-xs font-semibold text-slate-400">
              <span>Critical Issues: <strong className={criticalCount > 0 ? 'text-rose-400' : 'text-slate-200'}>{criticalCount}</strong></span>
              <span>•</span>
              <span>Total Findings: <strong className="text-slate-200">{totalFindings}</strong></span>
            </div>
            <div className="mt-4 flex items-center justify-center md:justify-start gap-3">
              <button
                onClick={() => window.open('http://127.0.0.1:8787/api/report/certificate', '_blank')}
                className="px-3.5 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20 text-xs font-bold text-white transition-all flex items-center gap-1.5 cursor-pointer shadow-sm"
              >
                <span>📜 Download Ship Certificate</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right: Security Score Gauge */}
        <div className="flex items-center gap-4 bg-black/30 border border-slate-800/80 px-6 py-4 rounded-2xl shadow-inner">
          <div className="relative w-24 h-24 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 96 96">
              {/* Background circle */}
              <circle
                cx="48"
                cy="48"
                r={radius}
                className="stroke-slate-800"
                strokeWidth="7"
                fill="transparent"
              />
              {/* Animated Progress circle */}
              <circle
                cx="48"
                cy="48"
                r={radius}
                stroke={scoreStrokeColor}
                strokeWidth="7"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-2xl font-black text-white">{score}</span>
              <span className="text-[9px] uppercase font-bold text-slate-400">/ 100</span>
            </div>
          </div>

          <div>
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Security Score</div>
            <div className={`text-sm font-bold ${config.text}`}>
              {isReady ? 'Excellent' : isReview ? 'Moderate Risk' : 'Critical Hazard'}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Weighted metric</div>
          </div>
        </div>
      </div>
    </div>
  );
};
