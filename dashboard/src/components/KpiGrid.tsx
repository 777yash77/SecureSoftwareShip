import React from 'react';
import { ScanSummary } from '../types';
import { AlertCircle, AlertTriangle, Shield, FileText, Clock, Bug } from 'lucide-react';

interface KpiGridProps {
  summary: ScanSummary;
}

export const KpiGrid: React.FC<KpiGridProps> = ({ summary }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
      {/* Total Findings */}
      <div className="bg-[#111827] border border-cyber-border rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-all">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">Total Findings</span>
          <Bug className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="mt-3">
          <div className="text-2xl font-black text-white">{summary.total_findings}</div>
          <p className="text-[11px] text-slate-500 mt-0.5">Across all scanners</p>
        </div>
      </div>

      {/* Critical Severity */}
      <div className="bg-[#111827] border border-rose-500/20 rounded-xl p-4 flex flex-col justify-between hover:border-rose-500/40 transition-all bg-gradient-to-b from-rose-950/10 to-transparent">
        <div className="flex items-center justify-between text-rose-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">Critical</span>
          <AlertCircle className="w-4 h-4" />
        </div>
        <div className="mt-3">
          <div className="text-2xl font-black text-rose-400">{summary.critical_count}</div>
          <p className="text-[11px] text-rose-300/70 mt-0.5">-25 pts penalty each</p>
        </div>
      </div>

      {/* High Severity */}
      <div className="bg-[#111827] border border-orange-500/20 rounded-xl p-4 flex flex-col justify-between hover:border-orange-500/40 transition-all bg-gradient-to-b from-orange-950/10 to-transparent">
        <div className="flex items-center justify-between text-orange-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">High</span>
          <AlertTriangle className="w-4 h-4" />
        </div>
        <div className="mt-3">
          <div className="text-2xl font-black text-orange-400">{summary.high_count}</div>
          <p className="text-[11px] text-orange-300/70 mt-0.5">-15 pts penalty each</p>
        </div>
      </div>

      {/* Medium Severity */}
      <div className="bg-[#111827] border border-amber-500/20 rounded-xl p-4 flex flex-col justify-between hover:border-amber-500/40 transition-all">
        <div className="flex items-center justify-between text-amber-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">Medium</span>
          <Shield className="w-4 h-4" />
        </div>
        <div className="mt-3">
          <div className="text-2xl font-black text-amber-400">{summary.medium_count}</div>
          <p className="text-[11px] text-slate-500 mt-0.5">-5 pts penalty each</p>
        </div>
      </div>

      {/* Low Severity */}
      <div className="bg-[#111827] border border-cyan-500/20 rounded-xl p-4 flex flex-col justify-between hover:border-cyan-500/40 transition-all">
        <div className="flex items-center justify-between text-cyan-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">Low</span>
          <Shield className="w-4 h-4" />
        </div>
        <div className="mt-3">
          <div className="text-2xl font-black text-cyan-400">{summary.low_count}</div>
          <p className="text-[11px] text-slate-500 mt-0.5">-2 pts penalty each</p>
        </div>
      </div>

      {/* Footprint */}
      <div className="bg-[#111827] border border-cyber-border rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition-all">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] uppercase font-bold tracking-wider">Footprint</span>
          <Clock className="w-4 h-4 text-slate-400" />
        </div>
        <div className="mt-3">
          <div className="text-base font-bold text-white">
            {summary.files_scanned} <span className="text-xs text-slate-400 font-normal">files</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            {summary.lines_scanned} LOC in {summary.scan_duration_ms}ms
          </p>
        </div>
      </div>
    </div>
  );
};
