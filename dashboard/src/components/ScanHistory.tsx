import React from 'react';
import { ScanResult } from '../types';
import { History, ShieldAlert, ShieldCheck, ShieldX, Clock } from 'lucide-react';

interface ScanHistoryProps {
  scans: ScanResult[];
  currentScanId: string;
  onSelectScan: (scan: ScanResult) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  scans,
  currentScanId,
  onSelectScan,
}) => {
  if (!scans || scans.length <= 1) {
    return null;
  }

  return (
    <div className="bg-[#111827] border border-cyber-border rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <History className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-bold text-white tracking-wide">Recent Scan History</h3>
      </div>

      <div className="flex items-center gap-3 overflow-x-auto pb-2 pt-1">
        {scans.map((scan) => {
          const isSelected = scan.scan_id === currentScanId;
          const isReady = scan.summary.ship_status === 'READY TO SHIP';
          const isBlocked = scan.summary.ship_status === 'BLOCKED';

          const statusColor = isReady
            ? 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20'
            : isBlocked
            ? 'text-rose-400 border-rose-500/30 bg-rose-950/20'
            : 'text-amber-400 border-amber-500/30 bg-amber-950/20';

          return (
            <button
              key={scan.scan_id}
              onClick={() => onSelectScan(scan)}
              className={`shrink-0 text-left p-3 rounded-lg border transition-all cursor-pointer ${
                isSelected
                  ? 'border-cyan-400 bg-cyan-950/20 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                  : 'border-slate-800 bg-[#090d16] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-3 text-xs mb-1">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusColor}`}>
                  {scan.summary.ship_status}
                </span>
                <span className="font-mono text-white font-bold">{scan.summary.security_score}/100</span>
              </div>
              <div className="text-[11px] text-slate-300 truncate max-w-[170px]" title={scan.target_path}>
                {scan.target_path}
              </div>
              <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(scan.timestamp).toLocaleTimeString()} ({scan.summary.total_findings} findings)
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
