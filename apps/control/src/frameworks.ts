// Built-in compliance framework catalogue (BP 9.1, 9.3). Signet Controls (SGC) are the hub; every entry
// below is a framework requirement (a spoke) with the Signet Controls that produce evidence for it.
//
// Licence rule (BP 9.3): only sources whose terms allow reuse are shipped. Public-domain and open
// texts ship official identifiers and titles; everything else ships identifiers plus summaries that
// Signet wrote itself. Paid or licence-restricted sources (ISO/IEC 42001, 27001, 27701, 23894, SOC 2,
// CIS Controls, CSA AICM, Secure Controls Framework) ship only as empty, locked entries (PLACEHOLDERS):
// the organisation loads its own licensed copy with the spreadsheet importer.
//
// Mapping relationship (NIST OLIR style) says how much of the requirement the Signet Control covers:
//   equivalent  - the control fully meets the requirement
//   subset_of   - the control meets part of the requirement (the usual case)
//   superset_of - the control meets the requirement and more
//   intersects  - partial overlap in both directions
// A requirement with no mapping is shown as a coverage gap, never as passing.
import { NIST_OFFICIAL_TEXT } from './nist-official-text';

export type Relationship = 'equivalent' | 'subset_of' | 'superset_of' | 'intersects';
export type Category = 'ai_risk' | 'ai_security' | 'ai_law' | 'security' | 'privacy' | 'resilience' | 'threat' | 'regional';
export type Applies = 'always' | 'eu_ai_act' | 'personal_data' | 'tenant';

export interface FrameworkDef {
  id: string;
  name: string;
  version: string;
  licence: string;
  ships: 'full_text' | 'summaries';
  category: Category;
  source_url: string;
  default_enabled: boolean;
  applies: Applies; // when the framework is attached to an agent at Classify
  notes?: string;
}

export interface MappingDef {
  control: string;
  rel: Relationship;
  note?: string;
}

export interface RequirementDef {
  framework_id: string;
  external_id: string;
  summary: string;
  maps: MappingDef[];
}

// Library pack version (BP 9.1, semantic versioning): raise it whenever frameworks, requirements, links or
// control definitions change. Major: something removed or renamed; minor: added; patch: wording.
export const LIBRARY_VERSION = '1.1.0';
export const LIBRARY_RELEASED = '2026-11-14';

export const FRAMEWORKS: FrameworkDef[] = [
  { id: 'nist-ai-rmf', name: 'NIST AI RMF 1.0', version: '1.0 (NIST AI 100-1)', licence: 'US government work, public domain', ships: 'full_text', category: 'ai_risk', source_url: 'https://doi.org/10.6028/NIST.AI.100-1', default_enabled: true, applies: 'always', notes: 'All 72 subcategories with NIST\'s official wording (Tables 1-4 of NIST AI 100-1).' },
  { id: 'nist-ai-600-1', name: 'NIST AI 600-1 Generative AI Profile', version: '2024', licence: 'US government work, public domain', ships: 'full_text', category: 'ai_risk', source_url: 'https://doi.org/10.6028/NIST.AI.600-1', default_enabled: true, applies: 'always', notes: 'The 12 generative AI risks with NIST\'s official definitions (section 1 of NIST AI 600-1).' },
  { id: 'owasp-llm', name: 'OWASP Top 10 for LLM Applications', version: '2025', licence: 'CC BY-SA 4.0, with attribution to the OWASP GenAI Security Project', ships: 'full_text', category: 'ai_security', source_url: 'https://genai.owasp.org/llm-top-10/', default_enabled: true, applies: 'always' },
  { id: 'owasp-agentic', name: 'OWASP Agentic AI Threats and Mitigations', version: '1.0 (2025)', licence: 'CC BY-SA 4.0, with attribution to the OWASP GenAI Security Project', ships: 'full_text', category: 'ai_security', source_url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/', default_enabled: true, applies: 'always' },
  { id: 'mitre-atlas', name: 'MITRE ATLAS', version: '2025', licence: 'Published openly by MITRE on GitHub; confirm the licence file at each update', ships: 'full_text', category: 'threat', source_url: 'https://atlas.mitre.org/', default_enabled: true, applies: 'always', notes: 'Technique names change between ATLAS releases; identifiers are stable.' },
  { id: 'eu-ai-act', name: 'EU AI Act (Regulation (EU) 2024/1689)', version: '2024, as amended by the Digital Omnibus (Regulation (EU) 2026/1744)', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'ai_law', source_url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj', default_enabled: true, applies: 'eu_ai_act', notes: 'The 2026 Digital Omnibus (in force 27 July 2026) moved the high-risk duties for Annex III systems to 2 December 2027 and for Annex I products to 2 August 2028, made AI literacy (Art. 4) a duty to take measures, and added two prohibited practices from 2 December 2026. Dates as reported by legal sources in November 2026; confirm against the consolidated text on EUR-Lex.' },
  { id: 'gdpr', name: 'GDPR (Regulation (EU) 2016/679)', version: '2016', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'privacy', source_url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj', default_enabled: true, applies: 'personal_data' },
  { id: 'nist-csf', name: 'NIST Cybersecurity Framework 2.0', version: '2.0', licence: 'US government work, public domain', ships: 'full_text', category: 'security', source_url: 'https://doi.org/10.6028/NIST.CSWP.29', default_enabled: true, applies: 'always' },
  { id: 'nist-800-53', name: 'NIST SP 800-53 Rev. 5 (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; OSCAL catalogue on NIST GitHub', ships: 'full_text', category: 'security', source_url: 'https://github.com/usnistgov/oscal-content', default_enabled: true, applies: 'always', notes: 'Ships the controls relevant to AI agents. Import the full OSCAL catalogue to see every control; extra controls are kept out of the score.' },
  { id: 'fedramp-moderate', name: 'FedRAMP Rev. 5 Moderate (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; baseline from FedRAMP legacy workbook (OSCAL profiles discontinued)', ships: 'full_text', category: 'security', source_url: 'https://github.com/FedRAMP/docs-legacy/blob/main/overrides/assets/LEGACY%20FedRAMP_Security_Controls_Baseline.xlsx', default_enabled: false, applies: 'tenant', notes: 'Only for US federal work. Membership checked against the FedRAMP legacy Rev. 5 baseline workbook (June 2026). FedRAMP is replacing it with the Consolidated Rules for 2026 (fedramp.gov/2026); import the full workbook with the spreadsheet importer if you need every control.' },
  { id: 'fedramp-high', name: 'FedRAMP Rev. 5 High (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; baseline from FedRAMP legacy workbook (OSCAL profiles discontinued)', ships: 'full_text', category: 'security', source_url: 'https://github.com/FedRAMP/docs-legacy/blob/main/overrides/assets/LEGACY%20FedRAMP_Security_Controls_Baseline.xlsx', default_enabled: false, applies: 'tenant', notes: 'Only for US federal work at high impact. Membership checked against the FedRAMP legacy Rev. 5 baseline workbook (June 2026); FedRAMP is replacing it with the Consolidated Rules for 2026.' },
  { id: 'fedramp-low', name: 'FedRAMP Rev. 5 Low (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; baseline from FedRAMP legacy workbook (OSCAL profiles discontinued)', ships: 'full_text', category: 'security', source_url: 'https://github.com/FedRAMP/docs-legacy/blob/main/overrides/assets/LEGACY%20FedRAMP_Security_Controls_Baseline.xlsx', default_enabled: false, applies: 'tenant', notes: 'Only for US federal work at low impact. Membership checked against the FedRAMP legacy Rev. 5 baseline workbook (June 2026); FedRAMP is replacing it with the Consolidated Rules for 2026.' },
  { id: 'fedramp-li-saas', name: 'FedRAMP Tailored LI-SaaS (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; baseline from FedRAMP legacy workbook (OSCAL profiles discontinued)', ships: 'full_text', category: 'security', source_url: 'https://github.com/FedRAMP/docs-legacy/blob/main/overrides/assets/LEGACY%20FedRAMP_Security_Controls_Baseline.xlsx', default_enabled: false, applies: 'tenant', notes: 'Low-impact SaaS. Each control shows its tailoring action from the FedRAMP legacy workbook (June 2026): Attest (the provider states it) or Document and Assess (an assessor tests it).' },
  { id: 'dora', name: 'DORA (Regulation (EU) 2022/2554)', version: '2022', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'resilience', source_url: 'https://eur-lex.europa.eu/eli/reg/2022/2554/oj', default_enabled: false, applies: 'tenant', notes: 'EU financial entities.' },
  { id: 'nis2', name: 'NIS2 (Directive (EU) 2022/2555)', version: '2022', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'resilience', source_url: 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj', default_enabled: false, applies: 'tenant', notes: 'EU essential and important entities.' },
  { id: 'sg-model-ai-gov', name: 'Singapore Model AI Governance Framework', version: '2nd edition (2020)', licence: 'Singapore government publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.pdpc.gov.sg/help-and-resources/2020/01/model-ai-governance-framework', default_enabled: false, applies: 'tenant' },
  { id: 'uk-ai-principles', name: 'UK AI regulation principles', version: '2023 white paper', licence: 'Open Government Licence v3.0', ships: 'summaries', category: 'regional', source_url: 'https://www.gov.uk/government/publications/ai-regulation-a-pro-innovation-approach', default_enabled: false, applies: 'tenant' },
  { id: 'ca-genai-code', name: 'Canada Voluntary Code of Conduct on Advanced Generative AI', version: '2023', licence: 'Government of Canada publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://ised-isde.canada.ca/site/ised/en/voluntary-code-conduct-responsible-development-and-management-advanced-generative-ai-systems', default_enabled: false, applies: 'tenant' },
  { id: 'au-ai-guardrails', name: 'Australia Guidance for AI Adoption (6 essential practices)', version: 'October 2025, updated July 2026', licence: 'Australian government publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.industry.gov.au/publications/guidance-for-ai-adoption', default_enabled: false, applies: 'tenant', notes: 'Published by the National AI Centre. Updates and replaces the 2024 Voluntary AI Safety Standard (10 guardrails), condensing them into six practices.' },
  { id: 'sg-imda-agentic', name: 'Singapore Model AI Governance Framework for Agentic AI', version: '1.5 (20 May 2026, updated 5 June 2026)', licence: 'Infocomm Media Development Authority publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.imda.gov.sg/assets/63438074-73f6-4dcc-a281-030f42642cf4.pdf', default_enabled: false, applies: 'tenant', notes: 'Voluntary guidance written for AI agents, organised in four dimensions: bound risks upfront, keep humans accountable, technical controls, and end-user responsibility.' },
  { id: 'us-co-ai-act', name: 'Colorado automated decision-making technology law (SB 26-189), deployer duties', version: 'May 2026; duties from 1 January 2027', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://leg.colorado.gov/bills/sb26-189', default_enabled: false, applies: 'tenant', notes: 'Replaced the 2024 Colorado AI Act (SB 24-205) before it took effect. Narrower and notice-based: notice, explanation of adverse decisions, data correction and human review, three-year records. The Attorney General enforces it.' },
  { id: 'us-tx-traiga', name: 'Texas Responsible AI Governance Act (HB 149)', version: 'In force 1 January 2026', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://capitol.texas.gov/BillLookup/History.aspx?LegSess=89R&Bill=HB149', default_enabled: false, applies: 'tenant', notes: 'Mostly intent-based prohibitions; disclosure duties for government agencies and health care providers. Enforced by the Attorney General; a defence exists for red-team testing or substantial compliance with the NIST AI RMF Generative AI Profile.' },
  { id: 'us-il-hb3773', name: 'Illinois Human Rights Act amendment on AI in employment (HB 3773)', version: 'In force 1 January 2026', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.ilga.gov/legislation/PublicActs/View/103-0804', default_enabled: false, applies: 'tenant', notes: 'Employers only. Paragraph numbers follow Section 2-102(L) as cited in law-firm summaries; the official ilga.gov text could not be reached when this was written (14 November 2026), so check it. The Department of Human Rights rules on notice timing and format were not final at that time.' },
  { id: 'us-ca-ccpa-admt', name: 'California CCPA regulations on automated decision-making technology', version: 'Approved September 2025; ADMT duties from 1 January 2027', licence: 'California regulations (11 CCR); Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://cppa.ca.gov/regulations/ccpa_updates.html', default_enabled: false, applies: 'tenant', notes: 'Applies to businesses covered by the CCPA that use ADMT for significant decisions about consumers, including employees.' },
  { id: 'us-nyc-ll144', name: 'New York City Local Law 144 (automated employment decision tools)', version: '2023', licence: 'US local law; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page', default_enabled: false, applies: 'tenant' },
  { id: 'us-ut-aipa', name: 'Utah Artificial Intelligence Policy Act', version: '2024, amended 2025 (SB 226, SB 332)', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://le.utah.gov/~2024/bills/static/SB0149.html', default_enabled: false, applies: 'tenant', notes: 'The 2025 amendments narrowed the disclosure duties and moved the law\'s repeal date to 1 July 2027.' },
  { id: 'us-sr-26-2', name: 'US interagency guidance on model risk management (SR 26-2)', version: 'April 2026 (replaces SR 11-7)', licence: 'US government work (Federal Reserve, FDIC, OCC), public domain; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm', default_enabled: false, applies: 'tenant', notes: 'Banking sector; most relevant to banks over $30 billion in assets. Guidance only: not enforceable on its own. Its footnote 3 puts generative and agentic AI outside its scope, so links to AI agents are partial; it applies to statistical and non-generative AI models.' },
  { id: 'uk-pra-ss1-23', name: 'UK PRA SS1/23 Model risk management principles for banks', version: 'April 2026 (updating May 2023)', licence: 'Bank of England publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.bankofengland.co.uk/prudential-regulation/publication/2023/may/model-risk-management-principles-for-banks-ss', default_enabled: false, applies: 'tenant', notes: 'Banking sector; applies to UK banks, building societies and PRA-designated investment firms with internal model approval. Models are defined broadly (outputs may be qualitative), so AI agents used for business decisions fall within it.' },
  { id: 'naic-ai-bulletin', name: 'NAIC Model Bulletin on the Use of AI Systems by Insurers', version: 'December 2023', licence: 'NAIC model bulletin, adopted by individual US states; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://content.naic.org/sites/default/files/inline-files/2023-12-4%20Model%20Bulletin_Adopted_0.pdf', default_enabled: false, applies: 'tenant', notes: 'Insurance sector. Applies where a state insurance regulator has adopted the bulletin. Requirement numbers follow its Section 3 (the written AIS Program).' },
  { id: 'sg-mas-ai-rm', name: 'MAS Guidelines on Artificial Intelligence Risk Management', version: '7 October 2026', licence: 'Monetary Authority of Singapore publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.mas.gov.sg/regulation/guidelines/guidelines-on-artificial-intelligence-risk-management-for-financial-institutions', default_enabled: false, applies: 'tenant', notes: 'Financial sector, Singapore. Covers all AI including generative AI and AI agents. Takes effect 7 October 2027 (Sections 3-4) and 7 October 2028 (Sections 5-6). The FEAT principles continue to apply alongside it.' },
];

// Licence-required frameworks (BP 9.3, 9.4). Signet ships only an empty, locked entry: name, version and
// why it is locked, with no requirement text. It cannot be switched on until the organisation loads its
// own licensed copy with the spreadsheet importer and records its licence; then requirements are linked
// to Signet Controls like any other framework. Signet-written content for these ids (for example the
// earlier ISO/IEC 42001 summaries) is removed by seed().
export interface PlaceholderDef { id: string; name: string; version: string; category: Category; reason: string; source_url: string }
export const PLACEHOLDERS: PlaceholderDef[] = [
  { id: 'iso-42001', name: 'ISO/IEC 42001 (AI management system)', version: '2023', category: 'ai_risk', reason: 'Copyrighted, paid ISO standard', source_url: 'https://www.iso.org/standard/81230.html' },
  { id: 'iso-23894', name: 'ISO/IEC 23894 (AI risk management)', version: '2023', category: 'ai_risk', reason: 'Copyrighted, paid ISO standard', source_url: 'https://www.iso.org/standard/77304.html' },
  { id: 'iso-27001', name: 'ISO/IEC 27001 (information security)', version: '2022', category: 'security', reason: 'Copyrighted, paid ISO standard', source_url: 'https://www.iso.org/standard/27001' },
  { id: 'iso-27701', name: 'ISO/IEC 27701 (privacy information management)', version: '2019', category: 'privacy', reason: 'Copyrighted, paid ISO standard', source_url: 'https://www.iso.org/standard/71670.html' },
  { id: 'soc2-tsc', name: 'SOC 2 Trust Services Criteria', version: '2017 (revised 2022)', category: 'security', reason: 'AICPA copyright', source_url: 'https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022' },
  { id: 'cis-controls', name: 'CIS Critical Security Controls', version: 'v8.1', category: 'security', reason: 'CC BY-NC-ND; commercial use needs a CIS licence', source_url: 'https://www.cisecurity.org/controls' },
  { id: 'csa-aicm', name: 'CSA AI Controls Matrix', version: 'v1.1', category: 'ai_security', reason: 'Free download; terms for use inside a product to be confirmed', source_url: 'https://cloudsecurityalliance.org/artifacts/ai-controls-matrix' },
  { id: 'scf', name: 'Secure Controls Framework', version: 'current', category: 'security', reason: 'Creative Commons terms to be confirmed before redistribution', source_url: 'https://securecontrolsframework.com/' },
];

// "SGC-X-001", "SGC-X-001~intersects" or "SGC-X-001~intersects~coverage note". Default relationship is subset_of.
const m = (spec: string): MappingDef => {
  const [control, rel, note] = spec.split('~') as [string, Relationship | undefined, string | undefined];
  return { control, rel: rel ?? 'subset_of', ...(note ? { note } : {}) };
};
const group = (fw: string, rows: [string, string, ...string[]][]): RequirementDef[] =>
  rows.map(([external_id, summary, ...maps]) => ({ framework_id: fw, external_id, summary, maps: maps.map(m) }));

// NIST SP 800-53 Rev. 5 controls relevant to AI agents, with official titles, shared with FedRAMP.
export const SP800_53_AI_SUBSET: [string, string, ...string[]][] = [
  ['AC-2', 'Account Management', 'SGC-GOV-001', 'SGC-INV-001'],
  ['AC-3', 'Access Enforcement', 'SGC-TOOL-004'],
  ['AC-6', 'Least Privilege', 'SGC-TOOL-004', 'SGC-TOOL-005'],
  ['AU-2', 'Event Logging', 'SGC-MON-001'],
  ['AU-3', 'Content of Audit Records', 'SGC-MON-001'],
  ['AU-6', 'Audit Record Review, Analysis, and Reporting', 'SGC-MON-004'],
  ['AU-9', 'Protection of Audit Information', 'SGC-MON-001'],
  ['AU-10', 'Non-repudiation', 'SGC-MON-001'],
  ['AU-12', 'Audit Record Generation', 'SGC-MON-001'],
  ['CA-7', 'Continuous Monitoring', 'SGC-MON-001', 'SGC-MON-004'],
  ['CM-8', 'System Component Inventory', 'SGC-INV-001', 'SGC-INV-002'],
  ['IA-5', 'Authenticator Management', 'SGC-IDN-002'],
  ['IA-9', 'Service Identification and Authentication', 'SGC-IDN-001'],
  ['IR-4', 'Incident Handling', 'SGC-RESP-002'],
  ['IR-6', 'Incident Reporting', 'SGC-RESP-003'],
  ['RA-3', 'Risk Assessment', 'SGC-RISK-001', 'SGC-RISK-002'],
  ['RA-5', 'Vulnerability Monitoring and Scanning', 'SGC-SUPPLY-001', 'SGC-SUPPLY-002'],
  ['SA-9', 'External System Services', 'SGC-MODEL-003'],
  ['SA-11', 'Developer Testing and Evaluation', 'SGC-SEC-001'],
  ['SC-7', 'Boundary Protection', 'SGC-TOOL-004', 'SGC-SELF-008'],
  ['SC-8', 'Transmission Confidentiality and Integrity', 'SGC-DATA-003'],
  ['SC-24', 'Fail in Known State', 'SGC-SELF-010'],
  ['SC-28', 'Protection of Information at Rest', 'SGC-DATA-004'],
  ['SI-4', 'System Monitoring', 'SGC-MON-004'],
  ['SI-10', 'Information Input Validation', 'SGC-TOOL-004'],
  ['SI-12', 'Information Management and Retention', 'SGC-MON-001'],
  ['SR-3', 'Supply Chain Controls and Processes', 'SGC-SUPPLY-001', 'SGC-MODEL-001'],
];
// Controls in the subset that are not in the FedRAMP Moderate baseline: AU-10 and SC-24 are High only;
// IA-9 is in no FedRAMP baseline. Checked on 2026-11-13 against FedRAMP's legacy baseline workbook
// (FedRAMP/docs-legacy, LEGACY FedRAMP_Security_Controls_Baseline.xlsx, sha256 aff2fa5e...): all 24
// built-in Moderate controls are in its Moderate Baseline sheet. FedRAMP no longer publishes OSCAL
// profiles (the GSA fedramp-automation repository is gone); it is moving to the Consolidated Rules 2026.
const NOT_IN_MODERATE = ['AU-10', 'IA-9', 'SC-24'];
// The same workbook's High, Low and Tailored LI-SaaS sheets (checked 2026-11-14). IA-9 is in none of them.
const NOT_IN_HIGH = ['IA-9'];
const NOT_IN_LOW = ['AC-6', 'AU-10', 'IA-9', 'SA-11', 'SC-24', 'SI-10'];
// LI-SaaS tailoring action per control: Attest = the provider attests; Document and Assess = an assessor tests it.
const LI_SAAS_ACTION: Record<string, string> = {
  'AC-2': 'Document and Assess', 'AC-3': 'Document and Assess', 'AU-2': 'Attest', 'AU-3': 'Document and Assess', 'AU-6': 'Document and Assess',
  'AU-9': 'Attest', 'AU-12': 'Attest', 'CA-7': 'Document and Assess', 'CM-8': 'Document and Assess', 'IA-5': 'Attest', 'IR-4': 'Document and Assess',
  'IR-6': 'Document and Assess', 'RA-3': 'Document and Assess', 'RA-5': 'Document and Assess', 'SA-9': 'Document and Assess', 'SC-7': 'Document and Assess',
  'SC-8': 'Document and Assess', 'SC-28': 'Document and Assess', 'SI-4': 'Document and Assess', 'SI-12': 'Attest', 'SR-3': 'Attest',
};

export const REQUIREMENTS: RequirementDef[] = [
  ...group('nist-ai-rmf', [
    ['GOVERN 1.1', 'Legal and regulatory requirements involving AI are understood, managed and documented', 'SGC-GOV-002'],
    ['GOVERN 1.2', 'Trustworthy AI characteristics are built into organisational policies and practices', 'SGC-GOV-002'],
    ['GOVERN 1.3', 'The level of risk management activity is set by the organisation\'s risk tolerance', 'SGC-RISK-001'],
    ['GOVERN 1.4', 'The risk management process and its outcomes are set through transparent policies and controls', 'SGC-GOV-002'],
    ['GOVERN 1.5', 'Ongoing monitoring and periodic review of the risk management process are planned, with clear roles', 'SGC-MON-001'],
    ['GOVERN 1.6', 'AI systems are inventoried, with resources set by risk priority', 'SGC-INV-001', 'SGC-INV-002'],
    ['GOVERN 1.7', 'AI systems are decommissioned and phased out safely', 'SGC-LIFE-004'],
    ['GOVERN 2.1', 'Roles, responsibilities and lines of communication for AI risk are documented', 'SGC-GOV-001'],
    ['GOVERN 2.2', 'Staff and partners receive AI risk management training', 'SGC-HUMAN-002'],
    ['GOVERN 2.3', 'Executive leadership takes responsibility for decisions about AI risk', 'SGC-GOV-002'],
    ['GOVERN 3.1', 'AI risk decisions are informed by a diverse team'],
    ['GOVERN 3.2', 'Roles for human-AI configurations and oversight are defined', 'SGC-HUMAN-001'],
    ['GOVERN 4.1', 'Policies foster a critical-thinking, safety-first mindset in AI work'],
    ['GOVERN 4.2', 'Teams document the risks and impacts of the AI they build, deploy and use', 'SGC-RISK-002'],
    ['GOVERN 4.3', 'Practices support AI testing, incident identification and information sharing', 'SGC-SEC-001', 'SGC-RESP-002'],
    ['GOVERN 5.1', 'Feedback from people outside the team about AI impacts is collected and used'],
    ['GOVERN 5.2', 'Reviewed feedback is fed back into system design and deployment'],
    ['GOVERN 6.1', 'Risks from third-party AI, data and software, including IP infringement, are addressed', 'SGC-MODEL-003'],
    ['GOVERN 6.2', 'Contingency plans cover failures of high-risk third-party data or AI systems', 'SGC-MODEL-003'],
    ['MAP 1.1', 'Intended purpose, context of use and applicable laws are understood and documented', 'SGC-RISK-001', 'SGC-VALUE-001'],
    ['MAP 1.2', 'The skills and backgrounds of the people involved are documented'],
    ['MAP 1.3', 'The organisation\'s mission and goals for the AI are understood', 'SGC-VALUE-001'],
    ['MAP 1.4', 'Business value and context of use are clearly defined', 'SGC-VALUE-001'],
    ['MAP 1.5', 'Organisational risk tolerances are set and documented', 'SGC-RISK-001'],
    ['MAP 1.6', 'System requirements are gathered from and understood by the relevant people'],
    ['MAP 2.1', 'The tasks the AI performs and how it performs them are defined', 'SGC-TOOL-005'],
    ['MAP 2.2', 'The system\'s limits, and how people use and oversee its output, are documented', 'SGC-HUMAN-001'],
    ['MAP 2.3', 'Testing, evaluation, verification and validation (TEVV) needs are identified', 'SGC-SEC-001'],
    ['MAP 3.1', 'Expected benefits of the AI are examined', 'SGC-VALUE-001'],
    ['MAP 3.2', 'Possible costs of errors, including non-money costs, are examined', 'SGC-VALUE-002'],
    ['MAP 3.3', 'The scope of use is set from the system\'s capability and risk category', 'SGC-TOOL-004'],
    ['MAP 3.4', 'Operator and practitioner proficiency requirements are defined', 'SGC-HUMAN-002'],
    ['MAP 3.5', 'Human oversight processes are defined, assessed and documented', 'SGC-HUMAN-001', 'SGC-TOOL-006'],
    ['MAP 4.1', 'Legal and technical risks of AI components, including third-party ones, are mapped', 'SGC-MODEL-001', 'SGC-SUPPLY-001'],
    ['MAP 4.2', 'Internal risk controls for AI components, including third-party technology, are identified', 'SGC-MODEL-002'],
    ['MAP 5.1', 'Likelihood and size of each identified impact are documented', 'SGC-RISK-002'],
    ['MAP 5.2', 'Regular engagement with affected people and feedback on impacts is practised'],
    ['MEASURE 1.1', 'Methods and metrics for the most significant AI risks are chosen', 'SGC-SEC-001'],
    ['MEASURE 1.2', 'Metrics and control effectiveness are reviewed regularly'],
    ['MEASURE 1.3', 'Independent assessors are involved in regular assessments', 'SGC-SEC-002'],
    ['MEASURE 2.1', 'Test sets, metrics and tools used in TEVV are documented', 'SGC-SEC-001'],
    ['MEASURE 2.2', 'Evaluations involving people meet requirements and represent the affected population'],
    ['MEASURE 2.3', 'Performance is measured under the conditions the system will be deployed in', 'SGC-SEC-001'],
    ['MEASURE 2.4', 'The system and its components are monitored in production', 'SGC-MON-001', 'SGC-MON-004'],
    ['MEASURE 2.5', 'The system is shown to be valid and reliable, with its limits documented', 'SGC-SEC-001'],
    ['MEASURE 2.6', 'Safety risks are evaluated regularly and the system fails safely', 'SGC-SELF-010'],
    ['MEASURE 2.7', 'Security and resilience are evaluated and documented', 'SGC-SEC-001', 'SGC-SEC-002', 'SGC-SELF-005'],
    ['MEASURE 2.8', 'Transparency and accountability risks are examined and documented', 'SGC-TRANS-001'],
    ['MEASURE 2.9', 'The model is explained and its output interpreted in context'],
    ['MEASURE 2.10', 'Privacy risk is examined and documented', 'SGC-DATA-002'],
    ['MEASURE 2.11', 'Fairness and bias are evaluated and documented', 'SGC-FAIR-001'],
    ['MEASURE 2.12', 'Environmental impact and sustainability are assessed'],
    ['MEASURE 2.13', 'The effectiveness of the TEVV metrics and processes is evaluated'],
    ['MEASURE 3.1', 'Existing, unexpected and emerging risks are tracked', 'SGC-MON-004'],
    ['MEASURE 3.2', 'Risks that are hard to measure with current methods are tracked'],
    ['MEASURE 3.3', 'Users can report problems and appeal outcomes'],
    ['MEASURE 4.1', 'Impact measurement is tied to the deployment context'],
    ['MEASURE 4.2', 'Trustworthiness results are reviewed with domain experts'],
    ['MEASURE 4.3', 'Improvements or declines in performance are identified and documented', 'SGC-MON-005'],
    ['MANAGE 1.1', 'A decision is made whether the AI meets its purpose and whether it should go ahead', 'SGC-LIFE-002'],
    ['MANAGE 1.2', 'Treatment of AI risks is prioritised by impact, likelihood and resources', 'SGC-RISK-001'],
    ['MANAGE 1.3', 'Responses to high-priority risks (mitigate, transfer, avoid, accept) are planned and documented', 'SGC-RISK-002~intersects'],
    ['MANAGE 1.4', 'Remaining risks to downstream users are documented'],
    ['MANAGE 2.1', 'Resources for AI risk management are weighed against non-AI alternatives'],
    ['MANAGE 2.2', 'The value of deployed AI systems is sustained', 'SGC-VALUE-001'],
    ['MANAGE 2.3', 'Procedures respond to and recover from newly found risks', 'SGC-RESP-002'],
    ['MANAGE 2.4', 'AI systems that behave outside intended use can be superseded, disengaged or deactivated', 'SGC-RESP-001', 'SGC-RESP-002', 'SGC-LIFE-004'],
    ['MANAGE 3.1', 'Risks and benefits of third-party AI resources are monitored and controlled', 'SGC-MODEL-001', 'SGC-MODEL-003'],
    ['MANAGE 3.2', 'Pre-trained models are part of regular monitoring', 'SGC-MODEL-002'],
    ['MANAGE 4.1', 'Post-deployment monitoring covers user input, appeal, override, decommissioning and incidents', 'SGC-MON-001', 'SGC-SELF-002'],
    ['MANAGE 4.2', 'Continual improvement activities are built into updates'],
    ['MANAGE 4.3', 'Incidents and errors are communicated to the people affected and tracked', 'SGC-RESP-002', 'SGC-RESP-003'],
  ]),
  ...group('nist-ai-600-1', [
    ['GAI-01', 'CBRN information or capabilities: easier access to chemical, biological, radiological or nuclear weapon knowledge'],
    ['GAI-02', 'Confabulation: confident but false or misleading content', 'SGC-MON-005'],
    ['GAI-03', 'Dangerous, violent or hateful content'],
    ['GAI-04', 'Data privacy: leakage or inference of personal data', 'SGC-DATA-001', 'SGC-DATA-002'],
    ['GAI-05', 'Environmental impacts of training and running models'],
    ['GAI-06', 'Harmful bias or homogenisation of outputs', 'SGC-FAIR-001'],
    ['GAI-07', 'Human-AI configuration: over-reliance, automation bias or poor oversight design', 'SGC-HUMAN-001', 'SGC-TOOL-006'],
    ['GAI-08', 'Information integrity: content that is hard to tell apart from fact', 'SGC-MON-005'],
    ['GAI-09', 'Information security: lowering the barrier for attacks and attacks on the AI itself', 'SGC-SEC-001', 'SGC-IDN-001'],
    ['GAI-10', 'Intellectual property: use or reproduction of protected material', 'SGC-MODEL-003'],
    ['GAI-11', 'Obscene, degrading or abusive content'],
    ['GAI-12', 'Value chain and component integration: risk from third-party models, data and services', 'SGC-SUPPLY-001', 'SGC-SUPPLY-002', 'SGC-MODEL-001'],
  ]),
  ...group('owasp-llm', [
    ['LLM01', 'Prompt Injection', 'SGC-SEC-001'],
    ['LLM02', 'Sensitive Information Disclosure', 'SGC-DATA-001', 'SGC-DATA-002'],
    ['LLM03', 'Supply Chain', 'SGC-MODEL-001', 'SGC-MODEL-002', 'SGC-SUPPLY-001', 'SGC-SUPPLY-002'],
    ['LLM04', 'Data and Model Poisoning', 'SGC-SUPPLY-001'],
    ['LLM05', 'Improper Output Handling', 'SGC-DATA-001'],
    ['LLM06', 'Excessive Agency', 'SGC-TOOL-004', 'SGC-TOOL-005', 'SGC-TOOL-006', 'SGC-IDN-001', 'SGC-IDN-002'],
    ['LLM07', 'System Prompt Leakage', 'SGC-IDN-002'],
    ['LLM08', 'Vector and Embedding Weaknesses'],
    ['LLM09', 'Misinformation', 'SGC-MON-005'],
    ['LLM10', 'Unbounded Consumption', 'SGC-VALUE-002'],
  ]),
  ...group('owasp-agentic', [
    ['T1', 'Memory Poisoning'],
    ['T2', 'Tool Misuse', 'SGC-TOOL-004', 'SGC-TOOL-006'],
    ['T3', 'Privilege Compromise', 'SGC-IDN-001', 'SGC-IDN-002'],
    ['T4', 'Resource Overload', 'SGC-VALUE-002'],
    ['T5', 'Cascading Hallucination Attacks', 'SGC-MON-005'],
    ['T6', 'Intent Breaking and Goal Manipulation', 'SGC-SEC-001'],
    ['T7', 'Misaligned and Deceptive Behaviours', 'SGC-MON-004'],
    ['T8', 'Repudiation and Untraceability', 'SGC-MON-001', 'SGC-INV-001'],
    ['T9', 'Identity Spoofing and Impersonation', 'SGC-IDN-001'],
    ['T10', 'Overwhelming Human in the Loop', 'SGC-HUMAN-003'],
    ['T11', 'Unexpected RCE and Code Attacks', 'SGC-TOOL-004'],
    ['T12', 'Agent Communication Poisoning'],
    ['T13', 'Rogue Agents in Multi-Agent Systems', 'SGC-INV-002', 'SGC-RESP-001'],
    ['T14', 'Human Attacks on Multi-Agent Systems'],
    ['T15', 'Human Manipulation', 'SGC-TRANS-001'],
  ]),
  ...group('mitre-atlas', [
    ['AML.T0051', 'LLM Prompt Injection', 'SGC-SEC-001'],
    ['AML.T0051.001', 'LLM Prompt Injection: Indirect', 'SGC-SEC-001', 'SGC-TOOL-006'],
    ['AML.T0054', 'LLM Jailbreak', 'SGC-SEC-001'],
    ['AML.T0056', 'LLM Meta Prompt Extraction'],
    ['AML.T0057', 'LLM Data Leakage', 'SGC-DATA-001', 'SGC-DATA-002'],
    ['AML.T0053', 'LLM Plugin Compromise', 'SGC-TOOL-004'],
    ['AML.T0055', 'Unsecured Credentials', 'SGC-IDN-002'],
    ['AML.T0034', 'Cost Harvesting', 'SGC-VALUE-002'],
    ['AML.T0029', 'Denial of ML Service', 'SGC-VALUE-002'],
    ['AML.T0010', 'ML Supply Chain Compromise', 'SGC-SUPPLY-001', 'SGC-SUPPLY-002', 'SGC-MODEL-001'],
    ['AML.T0020', 'Poison Training Data'],
    ['AML.T0024', 'Exfiltration via ML Inference API', 'SGC-DATA-001'],
    ['AML.T0048', 'External Harms', 'SGC-RESP-002'],
  ]),
  ...group('eu-ai-act', [
    ['Art. 4', 'AI literacy: take measures so that staff who operate AI have enough AI knowledge', 'SGC-HUMAN-002'],
    ['Art. 5', 'Prohibited AI practices are not placed on the market or used (from 2 December 2026 these include producing non-consensual intimate images and child sexual abuse material)', 'SGC-RISK-003~equivalent', 'SGC-SEC-003~intersects~unsafe content blocking stops these outputs at run time'],
    ['Art. 6', 'Classification rules for high-risk AI systems', 'SGC-RISK-001'],
    ['Art. 9', 'Risk management system for high-risk AI', 'SGC-RISK-001', 'SGC-RISK-002', 'SGC-LIFE-002', 'SGC-FAIR-001'],
    ['Art. 10', 'Data and data governance for training, validation and testing data'],
    ['Art. 11', 'Technical documentation, kept up to date', 'SGC-LIFE-002'],
    ['Annex IV', 'Required content of the technical documentation', 'SGC-LIFE-002'],
    ['Art. 12', 'Record-keeping: automatic logging of events', 'SGC-INV-001', 'SGC-MON-001'],
    ['Art. 13', 'Transparency and information to deployers', 'SGC-TRANS-001'],
    ['Art. 14', 'Human oversight', 'SGC-TOOL-006', 'SGC-HUMAN-001', 'SGC-HUMAN-002', 'SGC-HUMAN-003', 'SGC-SELF-003'],
    ['Art. 15', 'Accuracy, robustness and cybersecurity', 'SGC-DATA-001', 'SGC-TOOL-004', 'SGC-SEC-001', 'SGC-SEC-002'],
    ['Art. 17', 'Quality management system', 'SGC-GOV-002'],
    ['Art. 19', 'Automatically generated logs kept for at least six months', 'SGC-MON-001'],
    ['Art. 26', 'Deployer duties: use as instructed, assign human oversight, monitor, keep logs', 'SGC-HUMAN-001', 'SGC-MON-001'],
    ['Art. 27', 'Fundamental rights impact assessment before deploying certain high-risk AI', 'SGC-RISK-002'],
    ['Art. 50', 'Transparency obligations: people told they interact with AI', 'SGC-TRANS-001'],
    ['Art. 72', 'Post-market monitoring', 'SGC-MON-004', 'SGC-MON-005'],
    ['Art. 73', 'Reporting of serious incidents', 'SGC-RESP-003'],
  ]),
  ...group('gdpr', [
    ['Art. 5', 'Principles: lawful, fair, transparent, purpose-limited, minimised, accurate, secure processing', 'SGC-DATA-001'],
    ['Art. 6', 'Lawful basis for processing'],
    ['Art. 9', 'Special categories of personal data', 'SGC-DATA-002'],
    ['Art. 13', 'Information given to the person when data is collected', 'SGC-TRANS-001'],
    ['Art. 22', 'Automated decisions with legal or similar effect: right to human involvement', 'SGC-TOOL-006', 'SGC-HUMAN-001'],
    ['Art. 25', 'Data protection by design and by default', 'SGC-DATA-002'],
    ['Art. 28', 'Processors: contracts and guarantees', 'SGC-MODEL-003'],
    ['Art. 30', 'Records of processing activities', 'SGC-INV-001'],
    ['Art. 32', 'Security of processing', 'SGC-DATA-001', 'SGC-IDN-001'],
    ['Art. 33', 'Personal data breach notified to the authority within 72 hours', 'SGC-RESP-003'],
    ['Art. 35', 'Data protection impact assessment', 'SGC-RISK-002'],
    ['Art. 44', 'Transfers of personal data outside the EU'],
  ]),
  ...group('nist-csf', [
    ['GV.OC', 'Organizational Context', 'SGC-VALUE-001'],
    ['GV.RM', 'Risk Management Strategy', 'SGC-RISK-001'],
    ['GV.RR', 'Roles, Responsibilities, and Authorities', 'SGC-GOV-001'],
    ['GV.PO', 'Policy', 'SGC-GOV-002'],
    ['GV.OV', 'Oversight'],
    ['GV.SC', 'Cybersecurity Supply Chain Risk Management', 'SGC-MODEL-003', 'SGC-SUPPLY-001', 'SGC-SUPPLY-002'],
    ['ID.AM', 'Asset Management', 'SGC-INV-001', 'SGC-INV-002'],
    ['ID.RA', 'Risk Assessment', 'SGC-RISK-002'],
    ['ID.IM', 'Improvement'],
    ['PR.AA', 'Identity Management, Authentication, and Access Control', 'SGC-IDN-001', 'SGC-IDN-002', 'SGC-TOOL-004'],
    ['PR.AT', 'Awareness and Training', 'SGC-HUMAN-002'],
    ['PR.DS', 'Data Security', 'SGC-DATA-001', 'SGC-DATA-002'],
    ['PR.PS', 'Platform Security'],
    ['PR.IR', 'Technology Infrastructure Resilience'],
    ['DE.CM', 'Continuous Monitoring', 'SGC-MON-001', 'SGC-MON-004'],
    ['DE.AE', 'Adverse Event Analysis', 'SGC-MON-004'],
    ['RS.MA', 'Incident Management', 'SGC-RESP-002'],
    ['RS.AN', 'Incident Analysis'],
    ['RS.CO', 'Incident Response Reporting and Communication', 'SGC-RESP-003'],
    ['RS.MI', 'Incident Mitigation', 'SGC-RESP-001'],
    ['RC.RP', 'Incident Recovery Plan Execution'],
    ['RC.CO', 'Incident Recovery Communication'],
  ]),
  ...group('nist-800-53', SP800_53_AI_SUBSET),
  ...group('fedramp-moderate', SP800_53_AI_SUBSET.filter(([id]) => !NOT_IN_MODERATE.includes(id))),
  ...group('fedramp-high', SP800_53_AI_SUBSET.filter(([id]) => !NOT_IN_HIGH.includes(id))),
  ...group('fedramp-low', SP800_53_AI_SUBSET.filter(([id]) => !NOT_IN_LOW.includes(id))),
  ...group('fedramp-li-saas', SP800_53_AI_SUBSET.filter(([id]) => LI_SAAS_ACTION[id]).map(([id, title, ...maps]) => [id, `${title} (LI-SaaS: ${LI_SAAS_ACTION[id]})`, ...maps] as [string, string, ...string[]])),
  ...group('dora', [
    ['Art. 5', 'Management body defines, approves and oversees the ICT risk framework', 'SGC-GOV-002'],
    ['Art. 6', 'ICT risk management framework', 'SGC-RISK-001'],
    ['Art. 8', 'Identification of ICT assets, functions and dependencies', 'SGC-INV-001', 'SGC-INV-002'],
    ['Art. 9', 'Protection and prevention, including access control', 'SGC-TOOL-004', 'SGC-IDN-001'],
    ['Art. 10', 'Detection of anomalous activities', 'SGC-MON-004'],
    ['Art. 11', 'Response and recovery', 'SGC-RESP-001', 'SGC-RESP-002'],
    ['Art. 17', 'ICT-related incident management process', 'SGC-RESP-002'],
    ['Art. 19', 'Reporting of major ICT-related incidents', 'SGC-RESP-003'],
    ['Art. 24', 'Digital operational resilience testing', 'SGC-SEC-001', 'SGC-RESP-001'],
    ['Art. 28', 'Management of ICT third-party risk', 'SGC-MODEL-003'],
    ['Art. 30', 'Key contractual provisions with ICT third-party providers', 'SGC-MODEL-003'],
  ]),
  ...group('nis2', [
    ['Art. 20', 'Management bodies approve and oversee cybersecurity measures and are trained', 'SGC-GOV-002', 'SGC-HUMAN-002'],
    ['Art. 21', 'Cybersecurity risk-management measures, including supply chain security', 'SGC-RISK-001', 'SGC-TOOL-004', 'SGC-MON-001', 'SGC-SUPPLY-001'],
    ['Art. 23', 'Incident reporting: early warning in 24 hours, notification in 72 hours', 'SGC-RESP-003'],
  ]),
  ...group('sg-model-ai-gov', [
    ['Area 1', 'Internal governance structures and measures', 'SGC-GOV-001', 'SGC-GOV-002'],
    ['Area 2', 'Level of human involvement in AI-augmented decisions', 'SGC-HUMAN-001', 'SGC-TOOL-006'],
    ['Area 3', 'Operations management', 'SGC-MON-001', 'SGC-SEC-001'],
    ['Area 4', 'Stakeholder interaction and communication', 'SGC-TRANS-001'],
  ]),
  ...group('uk-ai-principles', [
    ['P1', 'Safety, security and robustness', 'SGC-SEC-001'],
    ['P2', 'Appropriate transparency and explainability', 'SGC-TRANS-001'],
    ['P3', 'Fairness', 'SGC-FAIR-001'],
    ['P4', 'Accountability and governance', 'SGC-GOV-001'],
    ['P5', 'Contestability and redress'],
  ]),
  ...group('ca-genai-code', [
    ['Accountability', 'Accountability: a risk management framework proportionate to the system', 'SGC-GOV-001'],
    ['Safety', 'Safety: assess and reduce risks of harmful use', 'SGC-SEC-001'],
    ['Fairness', 'Fairness and equity: assess and reduce biased output', 'SGC-FAIR-001'],
    ['Transparency', 'Transparency: people can tell when they deal with AI', 'SGC-TRANS-001'],
    ['Oversight', 'Human oversight and monitoring after deployment', 'SGC-HUMAN-001', 'SGC-MON-004'],
    ['Robustness', 'Validity and robustness: the system works as intended and is secure', 'SGC-SEC-001'],
  ]),
  ...group('au-ai-guardrails', [
    ['Practice 1', 'Decide who is accountable: a senior owner for AI governance and a policy for responsible use', 'SGC-GOV-001', 'SGC-GOV-002'],
    ['Practice 2', 'Understand impacts and plan for them, including ways for people to report problems or challenge AI decisions', 'SGC-RISK-002', 'SGC-HUMAN-005'],
    ['Practice 3', 'Measure and manage risks: screen for high-risk uses and scale controls to the risk', 'SGC-RISK-001', 'SGC-RISK-003~intersects'],
    ['Practice 4', 'Share essential information: keep a register of AI systems, say where AI is used and be able to explain outcomes', 'SGC-INV-001', 'SGC-TRANS-001', 'SGC-SELF-007~intersects'],
    ['Practice 5', 'Test before deployment and monitor afterwards', 'SGC-SEC-001', 'SGC-MON-004', 'SGC-MON-005~intersects'],
    ['Practice 6', 'Maintain human control: meaningful oversight, override points and fallbacks for critical functions', 'SGC-HUMAN-001', 'SGC-TOOL-006', 'SGC-RESP-001'],
  ]),
  ...group('sg-imda-agentic', [
    ['2.1.1', 'Choose suitable use cases for agents, weighing impact, autonomy and how reversible their actions are', 'SGC-RISK-001', 'SGC-RISK-002', 'SGC-RISK-003~intersects'],
    ['2.1.2', 'Bound risks by design: set each agent\'s limits and permissions (tools, data, identity) to the least it needs', 'SGC-TOOL-004', 'SGC-TOOL-005', 'SGC-IDN-001', 'SGC-IDN-002~intersects'],
    ['2.2.1', 'Allocate responsibilities clearly inside the organisation and with providers and vendors', 'SGC-GOV-001', 'SGC-MODEL-003~intersects'],
    ['2.2.2', 'Design for meaningful human oversight, with checkpoints before high-impact actions', 'SGC-TOOL-006', 'SGC-HUMAN-001', 'SGC-HUMAN-003'],
    ['2.3.1', 'Use technical controls during design and development, preferring deterministic rules over prompt instructions', 'SGC-TOOL-004', 'SGC-SEC-004', 'SGC-DATA-001~intersects'],
    ['2.3.2', 'Test agents before deployment, including whole workflows and multi-agent set-ups', 'SGC-SEC-001', 'SGC-SEC-002~intersects'],
    ['2.3.3', 'When deployed, monitor and test continuously, with the ability to intervene or stop an agent', 'SGC-MON-001', 'SGC-MON-004', 'SGC-RESP-001'],
    ['2.4.2', 'People who interact with agents know it, and can reach a human when needed', 'SGC-TRANS-001', 'SGC-HUMAN-005~intersects'],
    ['2.4.3', 'People who build agents into their work understand the agents\' limits and are trained to use them', 'SGC-HUMAN-002'],
  ]),
  ...group('us-co-ai-act', [
    ['6-1-1703', 'Keep records that show compliance for at least three years, such as version identifiers and change logs', 'SGC-MON-001', 'SGC-MODEL-002~intersects'],
    ['6-1-1704(1)-(2)', 'Before an automated decision tool materially influences a consequential decision, tell the consumer at the point of interaction', 'SGC-TRANS-001'],
    ['6-1-1704(3)', 'Within 30 days of an adverse decision, explain in plain language the decision and the role the tool played', 'SGC-HUMAN-005~intersects~the appeal route says where people ask; the explanation is sent by the organisation', 'SGC-RISK-002~intersects'],
    ['6-1-1705(1)(a)(I)', 'Let the consumer see and correct inaccurate personal data used in the decision', 'SGC-HUMAN-005~intersects~the appeal route also takes correction requests; data is corrected in the organisation\'s own systems'],
    ['6-1-1705(1)(a)(II)', 'Offer meaningful human review and reconsideration of an adverse decision', 'SGC-HUMAN-005'],
    ['6-1-1702', 'Receive and keep the developer\'s documentation: intended uses, training data categories, known limits and how to review outputs', 'SGC-SUPPLY-001~intersects~keep the developer documentation with the agent\'s AIBOM'],
  ]),
  ...group('us-tx-traiga', [
    ['552.051', 'Government agencies, and providers of health care services, tell people they are interacting with an AI system', 'SGC-TRANS-001'],
    ['552.052', 'Do not deploy AI that aims to encourage self-harm, harm to others or crime', 'SGC-SEC-003', 'SGC-RISK-003~intersects'],
    ['552.053', 'Government entities may not use AI for social scoring', 'SGC-RISK-003'],
    ['552.054', 'Government entities may not identify people from biometric data without consent', 'SGC-RISK-003~intersects', 'SGC-DATA-001~intersects'],
    ['552.055', 'Do not deploy AI with the sole intent of infringing constitutional rights', 'SGC-RISK-003~intersects'],
    ['552.056', 'Do not deploy AI with the intent to discriminate unlawfully against a protected class', 'SGC-FAIR-001~intersects~the law requires intent; bias testing gives evidence either way'],
    ['552.057', 'Do not deploy AI to produce sexual deepfakes of real people or child sexual abuse material', 'SGC-SEC-003'],
    ['552.103', 'Be able to answer the Attorney General: purpose, data, inputs, outputs, metrics, limits, monitoring and safeguards', 'SGC-LIFE-002~intersects~the lifecycle record and audit packs hold these answers', 'SGC-SUPPLY-001~intersects'],
    ['552.105(e)', 'Defence: violations found through red-team testing, or substantial compliance with the NIST AI RMF Generative AI Profile', 'SGC-SEC-001~intersects', 'SGC-SEC-002~intersects~NIST AI 600-1 is in Signet\'s library'],
  ]),
  ...group('us-il-hb3773', [
    ['2-102(L)(1)', 'Do not use AI in recruiting, hiring, promotion, discipline, discharge or terms of employment in a way that discriminates, including using zip codes as a stand-in for a protected class', 'SGC-FAIR-001'],
    ['2-102(L)(2)', 'Tell employees and applicants when AI is used for these employment decisions', 'SGC-TRANS-001'],
  ]),
  ...group('us-ca-ccpa-admt', [
    ['7200', 'Businesses using automated decision-making technology (ADMT) for significant decisions (lending, housing, education, employment, healthcare) comply by 1 January 2027', 'SGC-INV-001~intersects~the intake records which agents make decisions about people and in which domain'],
    ['7150', 'Do a risk assessment before using ADMT for a significant decision', 'SGC-RISK-002'],
    ['7155', 'Review risk assessments at least every three years, and within 45 days of a material change', 'SGC-RISK-002~intersects', 'SGC-LIFE-002~intersects~a change to the seal reopens the lifecycle'],
    ['7157', 'Submit risk assessment information to the California Privacy Protection Agency', 'SGC-RISK-002~intersects~submission is done by the organisation; Signet keeps the assessment record'],
    ['7220', 'Give a pre-use notice about the ADMT and the rights to opt out and to access', 'SGC-TRANS-001'],
    ['7221', 'Let consumers opt out of ADMT, or instead offer an appeal to a human reviewer who can overturn the decision', 'SGC-HUMAN-005'],
    ['7222', 'On request, explain how the ADMT works and how it affected the decision about the consumer', 'SGC-HUMAN-005~intersects', 'SGC-SELF-007~intersects'],
  ]),
  ...group('us-nyc-ll144', [
    ['Bias audit', 'Independent bias audit within one year before using the tool', 'SGC-FAIR-001'],
    ['Audit summary', 'Publish a summary of the latest bias audit'],
    ['Notice', 'Notify candidates and employees that the tool is used', 'SGC-TRANS-001'],
  ]),
  ...group('us-ut-aipa', [
    ['Disclosure', 'Say that generative AI is being used when a consumer clearly asks; in regulated occupations, disclose up front for high-risk interactions (for example collecting health, financial or biometric data)', 'SGC-TRANS-001'],
  ]),
  // Sector guidance (BP 9.3 "sector regulator guidance (banking model risk, insurance)"). Numbers follow
  // each document; summaries are Signet's own words. Links are "intersects" where Signet covers part.
  ...group('us-sr-26-2', [
    ['III', 'Manage model risk in proportion to its size: more complex, material or uncertain models get more rigour', 'SGC-RISK-001~intersects', 'SGC-RISK-002~intersects'],
    ['IV Model development', 'Record each model\'s purpose, design, data and limits, and test it before use', 'SGC-LIFE-002~intersects', 'SGC-SEC-001~intersects'],
    ['IV Model use', 'Users understand a model\'s limits; it is used only for its intended purpose and its outputs are challenged', 'SGC-TOOL-004~intersects', 'SGC-HUMAN-001~intersects'],
    ['V Conceptual soundness', 'Before use, someone independent reviews the design, assumptions and data', 'SGC-LIFE-002~intersects'],
    ['V Outcomes analysis', 'Outputs are compared with real outcomes and benchmarks', 'SGC-MON-005~intersects', 'SGC-SEC-001~intersects'],
    ['V Ongoing monitoring', 'Performance and use are monitored after deployment and drift is investigated', 'SGC-MON-004', 'SGC-MON-001~intersects'],
    ['VI Roles and responsibilities', 'Board and senior management oversee model risk with clear roles and independent challenge', 'SGC-GOV-001~intersects', 'SGC-GOV-002~intersects'],
    ['VI Model inventory', 'A complete inventory of models in use, in development and retired', 'SGC-INV-001', 'SGC-INV-002~intersects', 'SGC-LIFE-004~intersects'],
    ['VI Documentation', 'Models, their validation and their use are documented well enough for someone new to understand them', 'SGC-LIFE-002~intersects', 'SGC-MON-001~intersects'],
    ['VII', 'Vendor and other third-party models: get documentation, validate as far as possible, and plan for the vendor failing', 'SGC-SUPPLY-001~intersects', 'SGC-MODEL-003~intersects', 'SGC-MODEL-002~intersects'],
  ]),
  ...group('uk-pra-ss1-23', [
    ['1.1', 'Model definition: a clear definition of what counts as a model, including AI and complex rule-based methods', 'SGC-INV-001~intersects'],
    ['1.2', 'Model inventory: a complete, up-to-date inventory of models and their uses', 'SGC-INV-001', 'SGC-INV-002~intersects'],
    ['1.3', 'Model tiering: models are tiered by materiality and complexity, and the tier sets the rigour', 'SGC-RISK-001'],
    ['2.1', 'Board responsibilities: the board sets model risk appetite and oversees the framework', 'SGC-GOV-002'],
    ['2.2', 'A named senior manager (SMF) is accountable for the model risk management framework', 'SGC-GOV-001~intersects'],
    ['2.3', 'Policies and procedures cover the whole model life cycle', 'SGC-GOV-002~intersects', 'SGC-LIFE-002~intersects'],
    ['2.4', 'Roles and responsibilities for owners, developers, users and validators are clear', 'SGC-GOV-001~intersects', 'SGC-GOV-003~intersects'],
    ['2.5', 'Internal audit assesses the model risk management framework', 'SGC-MON-001~intersects~the ledger and audit packs give internal audit the evidence'],
    ['2.6', 'Externally developed and vendor models are held to the same standards', 'SGC-SUPPLY-001~intersects', 'SGC-MODEL-003~intersects'],
    ['3.1', 'Model purpose and design are documented and justified', 'SGC-LIFE-002~intersects'],
    ['3.2', 'Data used is suitable, of good quality and governed', 'SGC-DATA-001~intersects', 'SGC-DATA-005~intersects'],
    ['3.3', 'Models are tested during development, including their limits', 'SGC-SEC-001'],
    ['3.4', 'Model adjustments and expert judgement are controlled and recorded', 'SGC-LIFE-002~intersects~changes to an agent\'s seal go through the lifecycle again'],
    ['3.5', 'Development documentation is complete enough to support validation', 'SGC-LIFE-002~intersects'],
    ['3.6', 'Supporting systems that run models are controlled', 'SGC-SUPPLY-001~intersects', 'SGC-MODEL-002~intersects'],
    ['4.1', 'An independent validation function with the authority and skills to challenge', 'SGC-LIFE-002~intersects~approval needs people independent of the build team'],
    ['4.2', 'Independent review of each model before use, proportionate to its tier', 'SGC-LIFE-002~intersects'],
    ['4.3', 'Process verification: the model works as intended in production', 'SGC-MON-001~intersects', 'SGC-SELF-007~intersects'],
    ['4.4', 'Model performance is monitored against thresholds', 'SGC-MON-004', 'SGC-MON-005~intersects'],
    ['4.5', 'Models are periodically revalidated', 'SGC-LIFE-001'],
    ['5.1', 'A controlled process for adjustments made after the model (post-model adjustments)', 'SGC-LIFE-002~intersects'],
    ['5.2', 'Use of a model can be restricted when it is not performing or not validated', 'SGC-TOOL-004', 'SGC-RESP-001~intersects~quarantine and kill stop an agent at once'],
    ['5.3', 'Exceptions are recorded and escalated', 'SGC-RESP-002~intersects', 'SGC-HUMAN-003~intersects'],
  ]),
  ...group('naic-ai-bulletin', [
    ['1.1', 'The AI program reduces the risk of adverse consumer outcomes, such as unfair discrimination or inaccurate decisions', 'SGC-FAIR-001', 'SGC-DATA-001~intersects'],
    ['1.2', 'The program covers governance, risk controls and internal audit', 'SGC-GOV-002~intersects'],
    ['1.3', 'Senior management is accountable for the program and reports to the board', 'SGC-GOV-001~intersects', 'SGC-GOV-002~intersects'],
    ['1.4', 'The program is proportionate to how much the insurer uses and relies on AI', 'SGC-RISK-001~intersects'],
    ['1.5', 'The program may sit inside enterprise risk management or stand alone', 'SGC-GOV-002~intersects'],
    ['1.6', 'AI use is covered across the insurance life cycle (product, pricing, underwriting, claims, fraud)', 'SGC-INV-001~intersects'],
    ['1.7', 'All phases of an AI system\'s life are covered, from design to retirement', 'SGC-LIFE-002', 'SGC-LIFE-004~intersects'],
    ['1.8', 'AI used for regulated insurance practices gets particular attention', 'SGC-RISK-002~intersects'],
    ['1.9', 'Consumers affected by AI are told it is used', 'SGC-TRANS-001'],
    ['2.1', 'Policies and procedures, including risk management and controls, at each stage', 'SGC-GOV-002~intersects'],
    ['2.2', 'Compliance with the program is documented', 'SGC-MON-001~intersects'],
    ['2.3', 'A governance structure with committees, authority, independence, escalation and training', 'SGC-GOV-001~intersects', 'SGC-GOV-003~intersects', 'SGC-HUMAN-002~intersects'],
    ['2.4', 'Predictive models: processes to detect and prevent unfair discrimination', 'SGC-FAIR-001'],
    ['3.1', 'Oversight and approval of developing, adopting or buying AI systems', 'SGC-LIFE-002'],
    ['3.2', 'Data practices: currency, lineage, quality, integrity and bias', 'SGC-DATA-001~intersects', 'SGC-FAIR-001~intersects'],
    ['3.3', 'Predictive models: inventory, documentation and checks such as robustness and drift', 'SGC-INV-001~intersects', 'SGC-MON-004~intersects'],
    ['3.4', 'AI outputs are validated, tested and retested', 'SGC-SEC-001', 'SGC-LIFE-001~intersects'],
    ['3.5', 'Non-public consumer information is protected', 'SGC-DATA-002', 'SGC-DATA-001~intersects'],
    ['3.6', 'Data and records are retained', 'SGC-MON-001~intersects'],
    ['3.7', 'Predictive models: a written description of intended goals and use', 'SGC-LIFE-002~intersects'],
    ['4.1', 'Due diligence on third parties and their AI systems and data', 'SGC-SUPPLY-001~intersects', 'SGC-MODEL-003'],
    ['4.2', 'Contracts with AI vendors give audit rights and require cooperation with regulators', 'SGC-MODEL-003~intersects~contract terms are kept by the organisation; Signet records provider terms reviews'],
    ['4.3', 'Those contract rights are actually used to confirm vendors comply', 'SGC-MODEL-003~intersects'],
  ]),
  ...group('sg-mas-ai-rm', [
    ['3.1-3.4', 'The board oversees AI risk and makes sure existing risk frameworks cover AI', 'SGC-GOV-002'],
    ['3.5', 'Senior management puts the AI risk framework into practice and reviews it regularly', 'SGC-GOV-001~intersects', 'SGC-GOV-002~intersects'],
    ['4.2-4.4', 'AI use is identified consistently, including AI built into other tools; unidentified AI stays within risk appetite', 'SGC-INV-002', 'SGC-INV-001~intersects'],
    ['4.5-4.9', 'An accurate inventory of AI use cases, systems and models with their key attributes', 'SGC-INV-001'],
    ['4.10-4.13', 'Each AI use case is assessed for risk materiality, before and after controls', 'SGC-RISK-001', 'SGC-RISK-002'],
    ['5.3', 'High-risk AI use cases have contingency plans', 'SGC-RESP-001', 'SGC-RESP-002~intersects'],
    ['5.4', 'Data used across the AI life cycle is fit for purpose and protected', 'SGC-DATA-001', 'SGC-DATA-002~intersects'],
    ['5.5-5.6', 'Transparency and explainability match the context of the use case', 'SGC-TRANS-001', 'SGC-SELF-007~intersects'],
    ['5.7-5.8', 'Fair outcomes are defined and fairness is assessed where relevant', 'SGC-FAIR-001'],
    ['5.9', 'Appropriate human oversight of AI, reviewed regularly', 'SGC-HUMAN-001', 'SGC-TOOL-006', 'SGC-HUMAN-003~intersects'],
    ['5.10-5.11', 'Third-party AI is managed; the institution stays responsible for using it', 'SGC-SUPPLY-001', 'SGC-MODEL-003~intersects'],
    ['5.12-5.13', 'AI systems and models are selected carefully; less understood ones get extra controls', 'SGC-MODEL-001~intersects', 'SGC-MODEL-002~intersects'],
    ['5.14-5.15', 'Evaluation and testing proportionate to risk; known limits are mitigated', 'SGC-SEC-001', 'SGC-SEC-002~intersects'],
    ['5.16', 'AI systems are secure and well governed (technology and cybersecurity risks)', 'SGC-SEC-004', 'SGC-DATA-003~intersects', 'SGC-IDN-001~intersects'],
    ['5.17', 'The development process is documented for reproducibility and audit', 'SGC-MON-001', 'SGC-SELF-007~intersects'],
    ['5.18-5.22', 'Pre-deployment reviews, independent for high-risk use cases, with findings resolved', 'SGC-LIFE-002'],
    ['5.23-5.24', 'Post-deployment monitoring and revalidation', 'SGC-MON-004', 'SGC-MON-005~intersects', 'SGC-LIFE-001~intersects'],
    ['5.25', 'Changes to AI are controlled', 'SGC-LIFE-002~intersects', 'SGC-MODEL-002~intersects'],
    ['5.26', 'AI is retired or decommissioned in a controlled way', 'SGC-LIFE-004'],
    ['6.1-6.2', 'Staff working with AI are competent and their skills are reviewed', 'SGC-HUMAN-002', 'SGC-GOV-003~intersects'],
    ['6.3', 'Technology infrastructure is adequate for the AI in use', 'SGC-SUPPLY-001~intersects', 'SGC-DATA-004~intersects'],
  ]),
];

// Mapping pass for requirements that had no Signet Control. Each entry is "SGC-X-001" (subset_of) or
// "SGC-X-001~intersects"; a third part after "~" is a note for the auditor. Where Signet only covers
// part of a duty, the relationship is "intersects" and the note says what the organisation still does.
const LATER_MAPS: Record<string, string[]> = {
  'nist-ai-rmf|GOVERN 3.1': ['SGC-GOV-003'],
  'nist-ai-rmf|GOVERN 4.1': ['SGC-GOV-003', 'SGC-GOV-002~intersects'],
  'nist-ai-rmf|GOVERN 5.1': ['SGC-HUMAN-005~intersects~appeal routes collect feedback from affected people', 'SGC-GOV-003~intersects'],
  'nist-ai-rmf|GOVERN 5.2': ['SGC-GOV-003~intersects', 'SGC-LIFE-002~intersects~changes go through the lifecycle again'],
  'nist-ai-rmf|MAP 1.2': ['SGC-GOV-003'],
  'nist-ai-rmf|MAP 1.6': ['SGC-LIFE-002~intersects~the Propose stage records purpose, users, data and tools'],
  'nist-ai-rmf|MAP 5.2': ['SGC-HUMAN-005~intersects', 'SGC-GOV-003~intersects'],
  'nist-ai-rmf|MEASURE 1.2': ['SGC-GOV-002~intersects', 'SGC-SELF-006~intersects~controls are evaluated automatically every 10 minutes; detectors reviewed monthly'],
  'nist-ai-rmf|MEASURE 2.2': ['SGC-FAIR-001~intersects'],
  'nist-ai-rmf|MEASURE 2.9': ['SGC-MON-005~intersects~answers checked against their sources', 'SGC-SELF-007~intersects~every Signet decision can be explained and replayed'],
  'nist-ai-rmf|MEASURE 2.12': ['SGC-VALUE-002~intersects~token use and cost per agent are metered; energy figures come from the model provider'],
  'nist-ai-rmf|MEASURE 2.13': ['SGC-SELF-004~intersects~detector benchmarks and champion/challenger'],
  'nist-ai-rmf|MEASURE 3.2': ['SGC-RISK-002~intersects'],
  'nist-ai-rmf|MEASURE 3.3': ['SGC-HUMAN-005'],
  'nist-ai-rmf|MEASURE 4.1': ['SGC-RISK-002~intersects', 'SGC-MON-004~intersects~each agent is measured against its own baseline'],
  'nist-ai-rmf|MEASURE 4.2': ['SGC-GOV-003~intersects', 'SGC-HUMAN-002~intersects'],
  'nist-ai-rmf|MANAGE 1.4': ['SGC-RISK-002~intersects~residual risks are recorded in the impact assessment'],
  'nist-ai-rmf|MANAGE 2.1': ['SGC-VALUE-001~intersects~the business case records why an AI agent is used'],
  'nist-ai-rmf|MANAGE 4.2': ['SGC-LIFE-002~intersects', 'SGC-SELF-006~intersects'],
  'nist-ai-600-1|GAI-01': ['SGC-SEC-003'],
  'nist-ai-600-1|GAI-03': ['SGC-SEC-003'],
  'nist-ai-600-1|GAI-05': ['SGC-VALUE-002~intersects~token use is metered per agent; energy figures come from the model provider'],
  'nist-ai-600-1|GAI-11': ['SGC-SEC-003'],
  'owasp-llm|LLM08': ['SGC-SEC-004~intersects~retrieved content is scored for hidden instructions', 'SGC-DATA-001~intersects~answers are scanned for sensitive data; the vector store itself is secured by the agent team'],
  'owasp-agentic|T1': ['SGC-SEC-004~intersects~tool and retrieved content is scored; an injected session is tainted for 60 minutes'],
  'owasp-agentic|T12': ['SGC-SEC-004~intersects', 'SGC-TOOL-004~intersects~agents call only tools and agents in their seal'],
  'owasp-agentic|T14': ['SGC-HUMAN-003~intersects', 'SGC-TOOL-006~intersects'],
  'mitre-atlas|AML.T0056': ['SGC-SEC-004', 'SGC-DATA-001~intersects~answers are scanned and secrets redacted'],
  'mitre-atlas|AML.T0020': ['SGC-SUPPLY-001~intersects~models are recorded in the AIBOM and pinned; Signet does not train models', 'SGC-MODEL-002~intersects'],
  'eu-ai-act|Art. 10': ['SGC-SUPPLY-001~intersects~a duty of the model provider; Signet records which model and version each agent uses'],
  'gdpr|Art. 6': ['SGC-DATA-005'],
  'gdpr|Art. 44': ['SGC-DATA-006', 'SGC-MODEL-003~intersects~provider terms record the region'],
  'nist-csf|GV.OV': ['SGC-GOV-002~intersects', 'SGC-GOV-001~intersects'],
  'nist-csf|ID.IM': ['SGC-SELF-006~intersects', 'SGC-RESP-002~intersects'],
  'nist-csf|PR.PS': ['SGC-MODEL-002~intersects', 'SGC-SUPPLY-001~intersects', 'SGC-SUPPLY-002~intersects'],
  'nist-csf|PR.IR': ['SGC-SELF-010~intersects~fail-safe when a detector or the model provider is down', 'SGC-RESP-001~intersects'],
  'nist-csf|RS.AN': ['SGC-RESP-002~intersects', 'SGC-SELF-007~intersects~any decision can be replayed from the ledger'],
  'nist-csf|RC.RP': ['SGC-RESP-001~intersects~quarantine and kill are released only by people after investigation'],
  'nist-csf|RC.CO': ['SGC-RESP-003~intersects'],
  'uk-ai-principles|P5': ['SGC-HUMAN-005'],
  'us-nyc-ll144|Audit summary': ['SGC-FAIR-002', 'SGC-FAIR-001~intersects~Signet holds the bias test results'],
};
for (const r of REQUIREMENTS) {
  const later = LATER_MAPS[`${r.framework_id}|${r.external_id}`];
  if (!later) continue;
  for (const spec of later) {
    const [control, rel, note] = spec.split('~') as [string, Relationship | undefined, string | undefined];
    if (!r.maps.some((x) => x.control === control)) r.maps.push({ control, rel: rel ?? 'subset_of', ...(note ? { note } : {}) });
  }
}

// NIST AI RMF and the Generative AI Profile ship NIST's own wording (public domain, BP 9.3 "full text"):
// the official text replaces Signet's short summary for each of these requirements.
for (const r of REQUIREMENTS) {
  const official = NIST_OFFICIAL_TEXT[`${r.framework_id}|${r.external_id}`];
  if (official) r.summary = official;
}

/**
 * Names of the enabled frameworks that apply to an agent with this risk profile (BP 6 Stage 2).
 * Built-in frameworks follow their `applies` rule; any other enabled framework (a licensed copy, an
 * OSCAL or spreadsheet import, a ServiceNow authority document) applies to every agent.
 */
export function applicableFrameworks(enabled: { id: string; name: string }[], profile: { eu_ai_act: boolean; personal_data: boolean }): string[] {
  return enabled.filter((e) => {
    const f = FRAMEWORKS.find((x) => x.id === e.id);
    return !f || f.applies === 'always' || f.applies === 'tenant' || (f.applies === 'eu_ai_act' && profile.eu_ai_act) || (f.applies === 'personal_data' && profile.personal_data);
  }).map((e) => FRAMEWORKS.find((x) => x.id === e.id)?.name ?? e.name);
}
