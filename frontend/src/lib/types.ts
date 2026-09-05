export type Locale = 'en' | 'de';
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type Localized = { en: string; de: string };

export interface ScenarioSummary {
  id: string;
  version: number;
  difficulty: 'foundation' | 'intermediate' | 'advanced';
  estimated_minutes: number;
  title: Localized;
  description: Localized;
  learning_objectives: Localized[];
  event_count: number;
  detection_count: number;
  asset_count: number;
}

export interface UserEntity {
  id: string;
  display_name: string;
  department: string;
  role: string;
  baseline: Localized;
}

export interface AssetEntity {
  id: string;
  hostname: string;
  asset_type: string;
  owner_user_id: string | null;
  operating_system: string | null;
  criticality: Severity;
}

export interface ContainmentOption {
  id: string;
  label: Localized;
  description: Localized;
}

export interface ScenarioDetail {
  metadata: Omit<ScenarioSummary, 'event_count' | 'detection_count' | 'asset_count'>;
  users: UserEntity[];
  assets: AssetEntity[];
  containment_options: ContainmentOption[];
  event_count: number;
  detection_count: number;
}

export interface NormalizedEvent {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: Severity;
  summary: string;
  user_id?: string;
  asset_id?: string;
  source_ip?: string;
  destination_ip?: string;
  domain?: string;
  process_name?: string;
  parent_process_name?: string;
  process_id?: string;
  parent_process_id?: string;
  session_id?: string;
  file_name?: string;
  bytes_out?: number;
  outcome?: string;
  mitre: string[];
  attributes: Record<string, unknown>;
}

export interface EventPage {
  items: NormalizedEvent[];
  total: number;
  offset: number;
  limit: number;
  facets: {
    sources: string[];
    event_types: string[];
    severities: string[];
    mitre: string[];
  };
}

export interface RelatedEvent {
  event_id: string;
  timestamp: string;
  summary: string;
  reasons: string[];
  strength: number;
}

export interface MatchDetail {
  field: string;
  operator: string;
  expected: unknown;
  actual: unknown;
  matched: boolean;
}

export interface Alert {
  id: string;
  rule_id: string;
  event_ids: string[];
  timestamp: string;
  severity: Severity;
  title: Localized;
  mitre: string[];
  match_details: MatchDetail[];
  false_positive_context: Localized;
  state: string;
  rationale: string;
}

export interface EventDetail {
  id: string;
  raw: Record<string, unknown> | string;
  normalized: Omit<NormalizedEvent, 'id'>;
  related: RelatedEvent[];
  alerts: Alert[];
}

export interface Detection {
  id: string;
  title: Localized;
  description: Localized;
  severity: Severity;
  mitre: string[];
  false_positive_context: Localized;
  match: 'all' | 'any';
  conditions: Array<{ field: string; operator: string; value: unknown }>;
  sigma: string;
}

export interface Evidence {
  id: string;
  event_id: string;
  note: string;
  created_at: string;
}

export interface InvestigationItem {
  id: string;
  kind: 'note' | 'hypothesis' | 'finding';
  text: string;
  evidence_event_ids: string[];
  created_at: string;
}

export interface Decision {
  classification: 'benign' | 'false_positive' | 'confirmed_incident';
  severity: 'low' | 'medium' | 'high' | 'critical';
  affected_user_ids: string[];
  affected_asset_ids: string[];
  mitre: string[];
  containment_action_ids: string[];
  rationale: string;
}

export interface Assessment {
  score: number;
  maximum_score: number;
  breakdown: Record<string, number>;
  expected: {
    classification: string;
    severity: string;
    affected_user_ids: string[];
    affected_asset_ids: string[];
    critical_event_ids: string[];
    mitre: string[];
    containment_action_ids: string[];
    false_positive_event_ids: string[];
    explanation: Localized;
    lessons: Localized[];
  };
  feedback: {
    missed_critical_evidence: string[];
    incorrectly_selected_evidence: string[];
  };
}

export interface Session {
  id: string;
  scenario_id: string;
  status: 'active' | 'submitted';
  created_at: string;
  updated_at: string;
  decision: Decision | null;
  assessment: Assessment | null;
  evidence: Evidence[];
  items: InvestigationItem[];
  alert_states: Record<string, { state: string; rationale: string; updated_at: string }>;
}
