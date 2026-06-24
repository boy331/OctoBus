import { defineService } from '@chaitin-ai/octobus-sdk';

import { handlers } from './topsec-waf.js';

export { handlers } from './topsec-waf.js';

export const service = defineService({ handlers });
