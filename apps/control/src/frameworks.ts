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

export const FRAMEWORKS: FrameworkDef[] = [
  { id: 'nist-ai-rmf', name: 'NIST AI RMF 1.0', version: '1.0 (NIST AI 100-1)', licence: 'US government work, public domain', ships: 'summaries', category: 'ai_risk', source_url: 'https://doi.org/10.6028/NIST.AI.100-1', default_enabled: true, applies: 'always' },
  { id: 'nist-ai-600-1', name: 'NIST AI 600-1 Generative AI Profile', version: '2024', licence: 'US government work, public domain', ships: 'summaries', category: 'ai_risk', source_url: 'https://doi.org/10.6028/NIST.AI.600-1', default_enabled: true, applies: 'always' },
  { id: 'owasp-llm', name: 'OWASP Top 10 for LLM Applications', version: '2025', licence: 'CC BY-SA 4.0, with attribution to the OWASP GenAI Security Project', ships: 'full_text', category: 'ai_security', source_url: 'https://genai.owasp.org/llm-top-10/', default_enabled: true, applies: 'always' },
  { id: 'owasp-agentic', name: 'OWASP Agentic AI Threats and Mitigations', version: '1.0 (2025)', licence: 'CC BY-SA 4.0, with attribution to the OWASP GenAI Security Project', ships: 'full_text', category: 'ai_security', source_url: 'https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/', default_enabled: true, applies: 'always' },
  { id: 'mitre-atlas', name: 'MITRE ATLAS', version: '2025', licence: 'Published openly by MITRE on GitHub; confirm the licence file at each update', ships: 'full_text', category: 'threat', source_url: 'https://atlas.mitre.org/', default_enabled: true, applies: 'always', notes: 'Technique names change between ATLAS releases; identifiers are stable.' },
  { id: 'eu-ai-act', name: 'EU AI Act (Regulation (EU) 2024/1689)', version: '2024', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'ai_law', source_url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj', default_enabled: true, applies: 'eu_ai_act' },
  { id: 'gdpr', name: 'GDPR (Regulation (EU) 2016/679)', version: '2016', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'privacy', source_url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj', default_enabled: true, applies: 'personal_data' },
  { id: 'nist-csf', name: 'NIST Cybersecurity Framework 2.0', version: '2.0', licence: 'US government work, public domain', ships: 'full_text', category: 'security', source_url: 'https://doi.org/10.6028/NIST.CSWP.29', default_enabled: true, applies: 'always' },
  { id: 'nist-800-53', name: 'NIST SP 800-53 Rev. 5 (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; OSCAL catalogue on NIST GitHub', ships: 'full_text', category: 'security', source_url: 'https://github.com/usnistgov/oscal-content', default_enabled: true, applies: 'always', notes: 'Ships the controls relevant to AI agents. Import the full OSCAL catalogue to see every control; extra controls are kept out of the score.' },
  { id: 'fedramp-moderate', name: 'FedRAMP Rev. 5 Moderate (AI-relevant controls)', version: 'Rev. 5', licence: 'US government work, public domain; OSCAL profiles in GSA fedramp-automation', ships: 'full_text', category: 'security', source_url: 'https://github.com/GSA/fedramp-automation', default_enabled: false, applies: 'tenant', notes: 'Only for US federal work. Import the official OSCAL profile to confirm baseline membership.' },
  { id: 'dora', name: 'DORA (Regulation (EU) 2022/2554)', version: '2022', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'resilience', source_url: 'https://eur-lex.europa.eu/eli/reg/2022/2554/oj', default_enabled: false, applies: 'tenant', notes: 'EU financial entities.' },
  { id: 'nis2', name: 'NIS2 (Directive (EU) 2022/2555)', version: '2022', licence: 'EU legal text, reuse permitted with attribution', ships: 'summaries', category: 'resilience', source_url: 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj', default_enabled: false, applies: 'tenant', notes: 'EU essential and important entities.' },
  { id: 'sg-model-ai-gov', name: 'Singapore Model AI Governance Framework', version: '2nd edition (2020)', licence: 'Singapore government publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.pdpc.gov.sg/help-and-resources/2020/01/model-ai-governance-framework', default_enabled: false, applies: 'tenant' },
  { id: 'uk-ai-principles', name: 'UK AI regulation principles', version: '2023 white paper', licence: 'Open Government Licence v3.0', ships: 'summaries', category: 'regional', source_url: 'https://www.gov.uk/government/publications/ai-regulation-a-pro-innovation-approach', default_enabled: false, applies: 'tenant' },
  { id: 'ca-genai-code', name: 'Canada Voluntary Code of Conduct on Advanced Generative AI', version: '2023', licence: 'Government of Canada publication; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://ised-isde.canada.ca/site/ised/en/voluntary-code-conduct-responsible-development-and-management-advanced-generative-ai-systems', default_enabled: false, applies: 'tenant' },
  { id: 'au-ai-guardrails', name: 'Australia Voluntary AI Safety Standard (10 guardrails)', version: '2024', licence: 'Australian government publication (CC BY 4.0); Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.industry.gov.au/publications/voluntary-ai-safety-standard', default_enabled: false, applies: 'tenant' },
  { id: 'us-co-ai-act', name: 'Colorado AI Act (SB 24-205), deployer duties', version: '2024', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://leg.colorado.gov/bills/sb24-205', default_enabled: false, applies: 'tenant', notes: 'Effective date has been postponed; check the current date before relying on it.' },
  { id: 'us-nyc-ll144', name: 'New York City Local Law 144 (automated employment decision tools)', version: '2023', licence: 'US local law; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page', default_enabled: false, applies: 'tenant' },
  { id: 'us-ut-aipa', name: 'Utah Artificial Intelligence Policy Act', version: '2024', licence: 'US state legislation; Signet summaries', ships: 'summaries', category: 'regional', source_url: 'https://le.utah.gov/~2024/bills/static/SB0149.html', default_enabled: false, applies: 'tenant' },
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

// "SGC-X-001" or "SGC-X-001~intersects". Default relationship is subset_of.
const m = (spec: string): MappingDef => {
  const [control, rel] = spec.split('~') as [string, Relationship | undefined];
  return { control, rel: rel ?? 'subset_of' };
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
  ['SC-8', 'Transmission Confidentiality and Integrity'],
  ['SC-24', 'Fail in Known State', 'SGC-SELF-010'],
  ['SC-28', 'Protection of Information at Rest'],
  ['SI-4', 'System Monitoring', 'SGC-MON-004'],
  ['SI-10', 'Information Input Validation', 'SGC-TOOL-004'],
  ['SI-12', 'Information Management and Retention', 'SGC-MON-001'],
  ['SR-3', 'Supply Chain Controls and Processes', 'SGC-SUPPLY-001', 'SGC-MODEL-001'],
];
// Controls in the subset that are not in the FedRAMP Moderate baseline (High only).
const NOT_IN_MODERATE = ['AU-10', 'IA-9', 'SC-24'];

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
    ['Art. 4', 'AI literacy: staff who operate AI have enough AI knowledge', 'SGC-HUMAN-002'],
    ['Art. 5', 'Prohibited AI practices are not placed on the market or used', 'SGC-RISK-003~equivalent'],
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
    ['G1', 'Accountability process, including governance and a strategy for compliance', 'SGC-GOV-001', 'SGC-GOV-002'],
    ['G2', 'Risk management process to identify and reduce risks', 'SGC-RISK-001'],
    ['G3', 'Protect AI systems and manage data quality and provenance', 'SGC-DATA-001'],
    ['G4', 'Test models and systems before deployment and monitor them afterwards', 'SGC-SEC-001', 'SGC-MON-004'],
    ['G5', 'Enable meaningful human control or intervention', 'SGC-HUMAN-001', 'SGC-RESP-001'],
    ['G6', 'Inform end users about AI-enabled decisions and interactions', 'SGC-TRANS-001'],
    ['G7', 'Let affected people challenge AI use or outcomes'],
    ['G8', 'Be transparent with other organisations across the AI supply chain', 'SGC-MODEL-003'],
    ['G9', 'Keep records so compliance can be assessed', 'SGC-MON-001', 'SGC-INV-001'],
    ['G10', 'Engage stakeholders, focusing on safety, diversity, inclusion and fairness', 'SGC-FAIR-001'],
  ]),
  ...group('us-co-ai-act', [
    ['Risk program', 'Risk management policy and program for high-risk AI', 'SGC-RISK-001'],
    ['Impact assessment', 'Impact assessment yearly and after significant changes', 'SGC-RISK-002'],
    ['Notice', 'Tell consumers when high-risk AI makes or helps make a consequential decision', 'SGC-TRANS-001'],
    ['Adverse decisions', 'Explain adverse decisions and offer correction and appeal'],
    ['Discrimination care', 'Use reasonable care to protect against algorithmic discrimination', 'SGC-FAIR-001'],
    ['AG report', 'Report discovered algorithmic discrimination to the Attorney General within 90 days', 'SGC-RESP-003'],
  ]),
  ...group('us-nyc-ll144', [
    ['Bias audit', 'Independent bias audit within one year before using the tool', 'SGC-FAIR-001'],
    ['Audit summary', 'Publish a summary of the latest bias audit'],
    ['Notice', 'Notify candidates and employees that the tool is used', 'SGC-TRANS-001'],
  ]),
  ...group('us-ut-aipa', [
    ['Disclosure', 'Disclose generative AI interaction when asked, and up front in regulated occupations', 'SGC-TRANS-001'],
  ]),
];

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
