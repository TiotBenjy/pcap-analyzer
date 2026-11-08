// Web worker of the Network layout: keeps ForceAtlas2 off the main thread. Loaded from the
// application origin (desktop CSP `script-src 'self'`), never from a blob: URL.

import { type LayoutInput, runLayout } from './forceLayout';

self.onmessage = (event: MessageEvent<LayoutInput>) => {
  self.postMessage(runLayout(event.data));
};
