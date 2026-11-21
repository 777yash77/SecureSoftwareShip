export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ShipStatus = 'READY TO SHIP' | 'NEEDS REVIEW' | 'BLOCKED';

export type FindingCategory = 'SECRETS' | 'SAST' | 'SCA' | 'IAC';

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet: string;
  owasp_category: string;
  cwe_id: string;
  description: string;
  remediation: string;
  auto_fix_hint?: string;
}

export interface ScanSummary {
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  files_scanned: number;
  lines_scanned: number;
  scan_duration_ms: number;
  security_score: number;
  ship_status: ShipStatus;
  owasp_breakdown: Record<string, number>;
  category_breakdown: Record<string, number>;
}

export interface ScanResult {
  scan_id: string;
  timestamp: string;
  target_path: string;
  summary: ScanSummary;
  findings: Finding[];
}
