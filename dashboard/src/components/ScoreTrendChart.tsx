import React from 'react';
import { TrendingUp, ShieldAlert, ShieldCheck } from 'lucide-react';

export interface TrendPoint {
  scan_id: string;
  timestamp: string;
  target_path: string;
  security_score: number;
  ship_status: string;
  critical_count: number;
  high_count: number;
  total_findings: number;
}

interface ScoreTrendChartProps {
  trendData: TrendPoint[];
}

export const ScoreTrendChart: React.FC<ScoreTrendChartProps> = ({ trendData }) => {
  if (!trendData || trendData.length < 2) {
    return null;
  }

  const width = 600;
  const height = 140;
  const padding = 30;

  // Calculate coordinates
  const minScore = 0;
  const maxScore = 100;

  const points = trendData.map((d, i) => {
    const x = padding + (i / (trendData.length - 1)) * (width - 2 * padding);
    const y = height - padding - ((d.security_score - minScore) / (maxScore - minScore)) * (height - 2 * padding);
    return { x, y, ...d };
  });

  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(' ');

  // Gradient area points
  const areaPoints = `${padding},${height - padding} ${polylinePoints} ${points[points.length - 1].x},${height - padding}`;

  const latestScore = trendData[trendData.length - 1].security_score;
  const firstScore = trendData[0].security_score;
  const scoreDelta = latestScore - firstScore;

  return (
    <div className="bg-[#111827] border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white tracking-wide">Security Score Progression Trend</h3>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Trend Delta:</span>
          <span
            className={`font-bold px-2 py-0.5 rounded ${
              scoreDelta >= 0 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
            }`}
          >
            {scoreDelta >= 0 ? `+${scoreDelta}` : scoreDelta} pts
          </span>
        </div>
      </div>

      <div className="relative w-full overflow-hidden">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-36">
          <defs>
            <linearGradient id="scoreTrendGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#1f293d" strokeDasharray="3 3" />
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="#1f293d" strokeDasharray="3 3" />
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#1f293d" />

          {/* Y Axis Labels */}
          <text x={padding - 8} y={padding + 4} fill="#64748b" fontSize="10" textAnchor="end">100</text>
          <text x={padding - 8} y={height / 2 + 3} fill="#64748b" fontSize="10" textAnchor="end">50</text>
          <text x={padding - 8} y={height - padding + 3} fill="#64748b" fontSize="10" textAnchor="end">0</text>

          {/* Shaded Area */}
          <polygon points={areaPoints} fill="url(#scoreTrendGrad)" />

          {/* Trend Line */}
          <polyline
            fill="none"
            stroke="#38bdf8"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            points={polylinePoints}
          />

          {/* Data Points */}
          {points.map((p, idx) => (
            <g key={p.scan_id || idx}>
              <circle
                cx={p.x}
                cy={p.y}
                r={idx === points.length - 1 ? 5 : 4}
                className={idx === points.length - 1 ? 'fill-cyan-400 stroke-white' : 'fill-slate-900 stroke-cyan-400'}
                strokeWidth="2"
              />
              <text
                x={p.x}
                y={p.y - 8}
                fill={p.security_score >= 80 ? '#34d399' : p.security_score >= 50 ? '#fbbf24' : '#f87171'}
                fontSize="10"
                fontWeight="bold"
                textAnchor="middle"
              >
                {p.security_score}
              </text>
            </g>
          ))}
        </svg>
      </div>
      <p className="text-[11px] text-slate-500 mt-1 text-center">
        Chronological security posture across {trendData.length} recorded scans (SQLite persistent history).
      </p>
    </div>
  );
};
