import React from 'react';
import { ScanSummary } from '../types';
import { Layers, ShieldCheck } from 'lucide-react';

interface SeverityChartsProps {
  summary: ScanSummary;
}

export const SeverityCharts: React.FC<SeverityChartsProps> = ({ summary }) => {
  const total = summary.total_findings || 1;

  const critPct = Math.round((summary.critical_count / total) * 100);
  const highPct = Math.round((summary.high_count / total) * 100);
  const medPct = Math.round((summary.medium_count / total) * 100);
  const lowPct = Math.round((summary.low_count / total) * 100);

  const owaspEntries = Object.entries(summary.owasp_breakdown || {}).sort((a, b) => b[1] - a[1]);
  const categoryEntries = Object.entries(summary.category_breakdown || {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Card 1: Severity & Category Breakdown */}
      <div className="bg-[#111827] border border-cyber-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">Severity Distribution & Categories</h3>
          </div>
          <span className="text-xs text-slate-400">{summary.total_findings} items total</span>
        </div>

        {/* Stacked Progress Bar */}
        <div className="h-3.5 w-full bg-slate-800 rounded-full overflow-hidden flex shadow-inner">
          {summary.critical_count > 0 && (
            <div
              style={{ width: `${critPct}%` }}
              className="bg-rose-500 transition-all duration-500"
              title={`Critical: ${summary.critical_count}`}
            />
          )}
          {summary.high_count > 0 && (
            <div
              style={{ width: `${highPct}%` }}
              className="bg-orange-500 transition-all duration-500"
              title={`High: ${summary.high_count}`}
            />
          )}
          {summary.medium_count > 0 && (
            <div
              style={{ width: `${medPct}%` }}
              className="bg-amber-500 transition-all duration-500"
              title={`Medium: ${summary.medium_count}`}
            />
          )}
          {summary.low_count > 0 && (
            <div
              style={{ width: `${lowPct}%` }}
              className="bg-cyan-500 transition-all duration-500"
              title={`Low: ${summary.low_count}`}
            />
          )}
        </div>

        {/* Legend */}
        <div className="grid grid-cols-4 gap-2 mt-4 text-xs font-medium">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />
            <span className="text-slate-300">Critical ({summary.critical_count})</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-orange-500" />
            <span className="text-slate-300">High ({summary.high_count})</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500" />
            <span className="text-slate-300">Med ({summary.medium_count})</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" />
            <span className="text-slate-300">Low ({summary.low_count})</span>
          </div>
        </div>

        {/* Category Badges */}
        <div className="mt-5 pt-4 border-t border-slate-800">
          <div className="text-[11px] uppercase font-bold text-slate-400 mb-2">Scanner Module Breakdown</div>
          <div className="flex flex-wrap gap-2">
            {categoryEntries.map(([cat, count]) => (
              <div
                key={cat}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#090d16] border border-slate-800 text-xs font-semibold"
              >
                <span className="text-slate-300">{cat}</span>
                <span className="px-1.5 py-0.5 rounded-md bg-cyan-500/20 text-cyan-300 font-bold text-[10px]">
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Card 2: OWASP Top 10 Mapping */}
      <div className="bg-[#111827] border border-cyber-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">OWASP Top 10 Violations</h3>
          </div>
          <span className="text-xs text-slate-400">{owaspEntries.length} categories</span>
        </div>

        <div className="space-y-3 max-h-[175px] overflow-y-auto pr-1">
          {owaspEntries.length === 0 ? (
            <p className="text-xs text-slate-500 text-center py-8">No OWASP violations identified.</p>
          ) : (
            owaspEntries.map(([category, count]) => {
              const pct = Math.min(100, Math.round((count / summary.total_findings) * 100));
              return (
                <div key={category} className="text-xs">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-slate-300 font-medium truncate max-w-[280px]" title={category}>
                      {category}
                    </span>
                    <span className="font-bold text-white ml-2">{count}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      style={{ width: `${pct}%` }}
                      className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-full"
                    />
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
