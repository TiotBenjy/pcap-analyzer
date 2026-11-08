import userEvent from '@testing-library/user-event';

/**
 * user-event session for the UI tests.
 *
 * By default user-event awaits a real `setTimeout(0)` between every pointer step and keystroke.
 * A single `type()` or dialog flow schedules dozens of them, and on a saturated machine each one
 * waits for the worker to be scheduled again: the test slows down for reasons unrelated to the
 * code under test. `delay: null` drops those timers; React updates are still flushed by
 * Testing Library's `act()` wrapping, and async results are awaited with `findBy*`.
 */
export function setupUser() {
  return userEvent.setup({ delay: null });
}
