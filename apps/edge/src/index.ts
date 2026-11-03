import { configFromEnv } from './config';
import { run } from './runner';

const config = configFromEnv(process.env);
const controller = new AbortController();
process.once('SIGINT', () => controller.abort());
process.once('SIGTERM', () => controller.abort());
console.log('Signet connector runner starting', { runner_id: config.runnerId, tools: config.tools.map((item) => item.tool.alias), control_url: config.controlUrl });
try {
  await run(config, controller.signal);
} catch (error) {
  if (!controller.signal.aborted) throw error;
}
