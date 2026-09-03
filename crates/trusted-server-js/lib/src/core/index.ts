// Public tsjs core bundle: sets up the global API, queue, and default methods.
export type {
  AdUnit,
  GptDiagnosticsApi,
  GptDiagnosticsExportV1,
  GptDiagnosticsRequestCycle,
  TsjsApi,
} from './types';
import type { TsjsApi } from './types';
import { addAdUnits } from './registry';
import { renderAdUnit, renderAllAdUnits } from './render';
import { log } from './log';
import { setConfig, getConfig } from './config';
import { requestAds } from './request';
import { installQueue } from './queue';

const VERSION = '0.1.0';

const w: Window & { tsjs?: TsjsApi } =
  ((globalThis as unknown as { window?: Window }).window as Window & {
    tsjs?: TsjsApi;
  }) || ({} as Window & { tsjs?: TsjsApi });

// Collect existing tsjs queued fns before we overwrite
const pending: Array<() => void> = Array.isArray(w.tsjs?.que) ? [...w.tsjs.que] : [];

// Create API and attach methods
const api: TsjsApi = (w.tsjs ??= {} as TsjsApi);
api.version = VERSION;
api.addAdUnits = addAdUnits;
api.renderAdUnit = renderAdUnit;
api.renderAllAdUnits = () => renderAllAdUnits();
api.log = log;
api.setConfig = setConfig;
api.getConfig = getConfig;
// Provide core requestAds API
api.requestAds = requestAds;
// Defensive defaults: the edge injects adSlots (head-open) and bids (before
// </body>) only when server-side ad templates run for the request. When template
// delivery is disabled or gated off (auction/consent, bots, prefetch), page code
// reading window.tsjs.bids / window.tsjs.adSlots must still see defined values
// instead of throwing. Injected scripts overwrite these wholesale.
api.adSlots ??= [];
api.bids ??= {};
// Point global tsjs
w.tsjs = api;

// Single shared queue
installQueue(api, w);

// Flush prior queued callbacks
for (const fn of pending) {
  try {
    if (typeof fn === 'function') {
      fn.call(api);
      log.debug('queue: flushed callback');
    }
  } catch {
    /* ignore queued callback error */
  }
}

log.info('tsjs initialized', {
  methods: [
    'setConfig',
    'getConfig',
    'requestAds',
    'addAdUnits',
    'renderAdUnit',
    'renderAllAdUnits',
  ],
});

// Draw a won bid directly into its slot element when no ad server is present.
//
// The server-side auction's normal render path runs through GPT: `adInit`
// applies bid targeting to GPT slots and refreshes them. A publisher page with
// no ad server has no `googletag` to define a slot, so a winning bid arrives in
// `window.tsjs.bids` with nothing to display it and the page stays blank.
//
// This runs only for bids carrying `debug_bid`, which the edge sets solely when
// `debug.inject_adm_for_testing` is configured, so a production page keeps the
// ad server in the loop and nothing renders twice.
function injectTestBidsWithoutAdServer(): void {
  const slots = api.adSlots ?? [];
  const bids = api.bids ?? {};
  for (const slot of slots) {
    const bid = bids[slot.id];
    if (!bid?.debug_bid || !bid.adm) continue;
    const target = document.getElementById(slot.div_id);
    if (!target) {
      log.warn('no element for slot', { id: slot.id, div_id: slot.div_id });
      continue;
    }
    // Already drawn, by this function or by the ad server path.
    if (target.getAttribute('data-tsjs-rendered') === '1') continue;
    target.innerHTML = bid.adm;
    target.setAttribute('data-tsjs-rendered', '1');
    log.info('rendered bid without an ad server', { id: slot.id });
  }
}

if (typeof document !== 'undefined') {
  // Bids are injected before `</body>`, so wait for the document rather than
  // reading them while the head script runs.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectTestBidsWithoutAdServer, { once: true });
  } else {
    injectTestBidsWithoutAdServer();
  }
}
