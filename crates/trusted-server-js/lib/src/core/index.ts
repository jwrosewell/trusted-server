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
// </body>) only when the server-side ad stack runs for the request. When it
// is gated off (kill switch, consent fail-closed, bots, prefetch), page code
// reading window.tsjs.bids / window.tsjs.adSlots must still see defined
// values instead of throwing. Injected scripts overwrite these wholesale.
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

// Permissions inspector.
//
// Shows the permission state the server resolved for this visit, in a panel
// over the publisher's page. The panel is an iframe onto `/_ts/permissions`,
// which is same-origin because the appliance serves it, so the publisher needs
// no component of their own and nothing about their page has to change.
//
// Opt-in through `?ts_permissions=1` so an ordinary visitor never sees it. It
// is a diagnostic for whoever runs the appliance, not a feature of the site.
const PERMISSIONS_FLAG = 'ts_permissions';

function showPermissionsPanel(): void {
  if (document.getElementById('tsjs-permissions-panel')) return;

  const panel = document.createElement('div');
  panel.id = 'tsjs-permissions-panel';
  panel.setAttribute(
    'style',
    'position:fixed;top:12px;right:12px;width:430px;height:70vh;z-index:2147483647;' +
      'background:#fff;border:1px solid #ccc;border-radius:6px;overflow:hidden;' +
      'box-shadow:0 6px 24px rgba(0,0,0,.28);display:flex;flex-direction:column'
  );

  const bar = document.createElement('div');
  bar.setAttribute(
    'style',
    'font:12px/1 -apple-system,Segoe UI,Arial,sans-serif;padding:8px 10px;' +
      'background:#232628;color:#fff;display:flex;justify-content:space-between;align-items:center'
  );
  bar.textContent = 'Trusted Server permissions';

  const close = document.createElement('button');
  close.textContent = 'close';
  close.setAttribute(
    'style',
    'font:11px -apple-system,Segoe UI,Arial,sans-serif;background:none;border:1px solid #666;' +
      'color:#fff;border-radius:3px;padding:2px 7px;cursor:pointer'
  );
  close.addEventListener('click', () => panel.remove());
  bar.appendChild(close);

  const frame = document.createElement('iframe');
  // Same origin, so it reports the permissions for a request carrying this
  // visitor's own cookies rather than an anonymous one.
  frame.src = '/_ts/permissions?view=html';
  frame.setAttribute('title', 'Permissions resolved for this request');
  frame.setAttribute('style', 'border:0;width:100%;flex:1');

  panel.appendChild(bar);
  panel.appendChild(frame);
  document.body.appendChild(panel);
}

if (typeof document !== 'undefined' && typeof location !== 'undefined') {
  const wanted = new URLSearchParams(location.search).get(PERMISSIONS_FLAG) === '1';
  if (wanted) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', showPermissionsPanel, { once: true });
    } else {
      showPermissionsPanel();
    }
  }
}
