export const ASSISTANT_ACTIONS = ['step_up', 'throttle', 'quarantine', 'kill', 'release'] as const;
export type AssistantActionName = typeof ASSISTANT_ACTIONS[number];

export interface AssistantMessage { role: 'user' | 'assistant'; content: string }
export interface AssistantRequest { messages: AssistantMessage[]; time_zone: string }
export interface AssistantAction {
  agent_id: string;
  agent_name: string;
  agent_handle: string;
  action: AssistantActionName;
}
export interface AssistantReply {
  message: string;
  model: string;
  action: AssistantAction | null;
  links: { label: string; href: string }[];
  period_days: number | null;
}

/** Bound conversation input; only human and assistant text is accepted, never system or tool messages. */
export function parseAssistantRequest(value: AssistantRequest): AssistantRequest {
  if (!value || !Array.isArray(value.messages) || value.messages.length < 1 || value.messages.length > 20) throw new TypeError('Send between 1 and 20 chat messages');
  if (typeof value.time_zone !== 'string' || !value.time_zone || value.time_zone.length > 100) throw new TypeError('Chat requires your IANA time zone');
  try { new Intl.DateTimeFormat('en', { timeZone: value.time_zone }); }
  catch (error) { if (error instanceof RangeError) throw new TypeError('Chat time zone must be a valid IANA identifier'); throw error; }
  let length = 0;
  const messages: AssistantMessage[] = value.messages.map(message => {
    if (!message || !['user', 'assistant'].includes(message.role) || typeof message.content !== 'string' || !message.content.trim() || message.content.length > (message.role === 'user' ? 6000 : 16000)) throw new TypeError('Chat messages require a user or assistant role; user messages allow 1–6000 characters and assistant messages allow 1–16000');
    length += message.content.length;
    return { role: message.role, content: message.content.trim() };
  });
  if (length > 24000) throw new TypeError('Chat history exceeds 24,000 characters; start a new chat');
  if (messages.at(-1)?.role !== 'user') throw new TypeError('The last chat message must be from the user');
  return { messages, time_zone: value.time_zone };
}

/** Validate responses before presenting an action or internal navigation link. */
export function parseAssistantReply(value: AssistantReply): AssistantReply {
  if (!value || typeof value.message !== 'string' || !value.message.trim() || value.message.length > 16000 || typeof value.model !== 'string' || !value.model || !Array.isArray(value.links) || value.links.length > 5) throw new TypeError('Signet assistant response requires a message, connected model and navigation links');
  if (value.period_days !== null && (!Number.isSafeInteger(value.period_days) || value.period_days < 1 || value.period_days > 90)) throw new TypeError('Assistant reporting period must be 1–90 days or null');
  for (const link of value.links) if (!link || typeof link.label !== 'string' || !link.label || typeof link.href !== 'string' || !/^\/(?:agents(?:\/[A-Za-z0-9_-]+)?|activity|settings\/(?:gateway-cost|models|setup-guide))$/.test(link.href)) throw new TypeError('Assistant navigation must point to a supported Signet page');
  if (value.action !== null) {
    const action = value.action;
    if (!action || !ASSISTANT_ACTIONS.includes(action.action) || typeof action.agent_id !== 'string' || !/^agt_[A-Za-z0-9]+$/.test(action.agent_id) || typeof action.agent_name !== 'string' || !action.agent_name || typeof action.agent_handle !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(action.agent_handle)) throw new TypeError('Assistant action requires a supported safety action and a registered agent identity');
  }
  return value;
}
