import React, { useState, useMemo } from 'react';
import { Finding, Severity, FindingCategory } from '../types';
import {
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  AlertCircle,
  Lightbulb,
  ExternalLink,
  Code2,
  Terminal,
  Sparkles,
  Zap,
} from 'lucide-react';

interface AdvisorAdvice {
  rule_id: string;
  title: string;
  analysis: string;
  exploit_scenario: string;
  remediation_strategy: string;
  patched_code: string;
  provider: string;
}

interface FindingsTableProps {
  findings: Finding[];
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings }) => {
  const [search, setSearch] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedFixId, setCopiedFixId] = useState<string | null>(null);
  const [advisorData, setAdvisorData] = useState<Record<string, AdvisorAdvice>>({});
  const [loadingAdvisorId, setLoadingAdvisorId] = useState<string | null>(null);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Severity filter
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) {
        return false;
      }
      // Category filter
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) {
        return false;
      }
      // Search text
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchRule = f.rule_id.toLowerCase().includes(q);
        const matchFile = f.file_path.toLowerCase().includes(q);
        const matchDesc = f.description.toLowerCase().includes(q);
        const matchCwe = f.cwe_id.toLowerCase().includes(q);
        if (!matchTitle && !matchRule && !matchFile && !matchDesc && !matchCwe) {
          return false;
        }
      }
      return true;
    });
  }, [findings, search, selectedSeverity, selectedCategory]);

  const copyToClipboard = (text: string, id: string, isFix: boolean = false) => {
    navigator.clipboard.writeText(text);
    if (isFix) {
      setCopiedFixId(id);
      setTimeout(() => setCopiedFixId(null), 2000);
    } else {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const fetchAdvisor = async (finding: Finding) => {
    if (advisorData[finding.id]) return;
    setLoadingAdvisorId(finding.id);
    try {
      const res = await fetch('http://127.0.0.1:8787/api/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding }),
      });
      if (res.ok) {
        const data: AdvisorAdvice = await res.json();
        setAdvisorData((prev) => ({ ...prev, [finding.id]: data }));
      }
    } catch (e) {
      console.warn('Failed to fetch advisor advice', e);
    } finally {
      setLoadingAdvisorId(null);
    }
  };

  const getSeverityBadge = (sev: Severity) => {
    const styles: Record<Severity, string> = {
      CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
      HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      LOW: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    };
    return (
      <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-extrabold tracking-wider border ${styles[sev]}`}>
        {sev}
      </span>
    );
  };

  return (
    <div className="bg-[#111827] border border-cyber-border rounded-xl p-5">
      {/* Control Bar: Search & Filters */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 mb-5 pb-5 border-b border-slate-800">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter findings by rule, title, file path, or CWE..."
            className="w-full bg-[#090d16] border border-slate-800 rounded-lg pl-9 pr-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 transition-all font-mono"
          />
        </div>

        {/* Severity Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                selectedSeverity === sev
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-[0_0_10px_rgba(6,182,212,0.3)]'
                  : 'bg-[#090d16] text-slate-400 border border-slate-800 hover:border-slate-700'
              }`}
            >
              {sev === 'ALL' ? `All (${findings.length})` : sev}
            </button>
          ))}
        </div>
      </div>

      {/* Category Sub-filter */}
      <div className="flex items-center gap-2 mb-4 text-xs">
        <span className="text-slate-500 flex items-center gap-1 font-semibold">
          <Filter className="w-3.5 h-3.5" /> Category:
        </span>
        {['ALL', 'SECRETS', 'SAST', 'SCA', 'IAC'].map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all cursor-pointer ${
              selectedCategory === cat
                ? 'bg-slate-700 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Findings List */}
      <div className="space-y-2.5">
        {filteredFindings.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-sm">
            ✨ No vulnerabilities matching the selected filters.
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div
                key={finding.id}
                className={`border rounded-xl transition-all ${
                  isExpanded
                    ? 'border-cyan-500/50 bg-[#0d1424] shadow-[0_0_20px_rgba(6,182,212,0.08)]'
                    : 'border-slate-800/80 bg-[#090d16]/70 hover:border-slate-700'
                }`}
              >
                {/* Header Row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="px-4 py-3.5 flex items-center justify-between gap-4 cursor-pointer select-none"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    {getSeverityBadge(finding.severity)}
                    {finding.confidence && (
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                        finding.confidence === 'HIGH' ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60' :
                        finding.confidence === 'MEDIUM' ? 'bg-amber-950/60 text-amber-400 border-amber-800/60' :
                        'bg-slate-800/60 text-slate-400 border-slate-700/60'
                      }`}>
                        {finding.confidence}
                      </span>
                    )}
                    <code className="text-xs text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/50 font-bold">
                      {finding.rule_id}
                    </code>
                    <span className="text-sm font-semibold text-slate-100 truncate">
                      {finding.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 shrink-0 text-xs">
                    <span className="text-slate-400 font-mono hidden sm:inline">
                      {finding.file_path}:{finding.line_start}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">
                      {finding.cwe_id}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-500" />
                    )}
                  </div>
                </div>

                {/* Expanded Drawer */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 space-y-4 text-xs">
                    {/* Description */}
                    <div>
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                        Description & Security Impact
                      </span>
                      <p className="mt-1 text-slate-300 leading-relaxed text-sm">
                        {finding.description}
                      </p>
                    </div>

                    {/* Code Snippet Box */}
                    <div className="rounded-lg border border-slate-800 bg-[#04070e] overflow-hidden">
                      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#090d16] border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                        <span className="flex items-center gap-1.5">
                          <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                          {finding.file_path} (Lines {finding.line_start}–{finding.line_end})
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(finding.code_snippet, finding.id);
                          }}
                          className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer font-sans"
                        >
                          {copiedId === finding.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-400">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy Snippet</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="p-3.5 overflow-x-auto text-slate-200 font-mono text-xs leading-relaxed">
                        <code>{finding.code_snippet}</code>
                      </pre>
                    </div>

                    {/* Remediation Box */}
                    <div className="p-3.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-slate-300">
                      <div className="flex items-center gap-1.5 text-cyan-400 font-bold mb-1">
                        <Lightbulb className="w-4 h-4" />
                        <span>Recommended Remediation</span>
                      </div>
                      <p className="text-xs leading-relaxed">{finding.remediation}</p>

                      {/* Auto-Fix Hint */}
                      {finding.auto_fix_hint && (
                        <div className="mt-2.5 pt-2 border-t border-cyan-900/40 flex items-center justify-between gap-3">
                          <div className="flex items-center gap-2">
                            <span className="text-[11px] font-bold text-emerald-400">Auto-Fix Suggestion:</span>
                            <code className="bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 px-2 py-0.5 rounded text-[11px] font-mono">
                              {finding.auto_fix_hint}
                            </code>
                          </div>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(finding.auto_fix_hint!, finding.id, true);
                            }}
                            className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold cursor-pointer"
                          >
                            {copiedFixId === finding.id ? (
                              <>
                                <Check className="w-3 h-3" />
                                <span>Copied Fix!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3" />
                                <span>Copy Fix</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}
                    </div>

                    {/* AI Explain & Fix Advisor Button & Drawer */}
                    <div className="pt-1">
                      {!advisorData[finding.id] ? (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            fetchAdvisor(finding);
                          }}
                          disabled={loadingAdvisorId === finding.id}
                          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-950/50 hover:bg-indigo-900/60 border border-indigo-500/40 text-indigo-300 hover:text-white text-xs font-bold transition-all shadow-[0_0_12px_rgba(99,102,241,0.2)] cursor-pointer"
                        >
                          <Sparkles className={`w-3.5 h-3.5 text-indigo-400 ${loadingAdvisorId === finding.id ? 'animate-spin' : ''}`} />
                          <span>{loadingAdvisorId === finding.id ? 'AI Advisor Analyzing...' : '✨ Ask AI Advisor / Explain & Fix'}</span>
                        </button>
                      ) : (
                        <div className="p-4 rounded-xl bg-gradient-to-br from-indigo-950/40 via-[#0d1424] to-[#090d16] border border-indigo-500/40 shadow-[0_0_20px_rgba(99,102,241,0.15)] space-y-3">
                          <div className="flex items-center justify-between pb-2 border-b border-indigo-900/50">
                            <div className="flex items-center gap-2 text-indigo-400 font-bold text-xs">
                              <Sparkles className="w-4 h-4 text-indigo-400" />
                              <span>AI Security Advisor Analysis ({advisorData[finding.id].provider})</span>
                            </div>
                            <span className="text-[10px] uppercase font-bold text-indigo-300/80 px-2 py-0.5 rounded bg-indigo-900/40 border border-indigo-700/50">
                              Verified
                            </span>
                          </div>

                          <div>
                            <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wide">Root Cause:</div>
                            <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">{advisorData[finding.id].analysis}</p>
                          </div>

                          <div>
                            <div className="text-[11px] font-bold text-rose-400 uppercase tracking-wide">Attack Vector & Exploit Scenario:</div>
                            <p className="text-xs text-slate-300 mt-0.5 leading-relaxed bg-black/40 p-2.5 rounded border border-rose-500/20">{advisorData[finding.id].exploit_scenario}</p>
                          </div>

                          {advisorData[finding.id].patched_code && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wide">Context-Aware Patched Code:</span>
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyToClipboard(advisorData[finding.id].patched_code, `${finding.id}-advisor-fix`, true);
                                  }}
                                  className="text-[11px] text-emerald-400 hover:text-emerald-300 font-bold flex items-center gap-1 cursor-pointer"
                                >
                                  {copiedFixId === `${finding.id}-advisor-fix` ? (
                                    <>
                                      <Check className="w-3 h-3" />
                                      <span>Copied Patch!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3 h-3" />
                                      <span>Copy Patched Code</span>
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre className="p-2.5 bg-black/60 rounded border border-emerald-500/30 text-emerald-300 font-mono text-xs overflow-x-auto">
                                <code>{advisorData[finding.id].patched_code}</code>
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Meta Classifications */}
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                      <span className="px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-slate-300 font-mono">
                        Classification: {finding.cwe_id}
                      </span>
                      <span className="px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700/60 text-slate-300">
                        {finding.owasp_category}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
