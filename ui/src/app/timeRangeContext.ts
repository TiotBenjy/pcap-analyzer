import { createContext } from 'react';

/**
 * True inside the application shell, where the router (and so the time range of the URL) is
 * available. Components rendered on their own (tests, previews) read false and skip the range.
 */
export const InRouterContext = createContext(false);
