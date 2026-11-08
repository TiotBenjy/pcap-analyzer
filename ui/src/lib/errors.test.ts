import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import i18n from '../i18n';
import { describeError } from './errors';

const t = i18n.t.bind(i18n);

describe('describeError', () => {
  it('translates common statuses and keeps the raw message as a detail', () => {
    expect(describeError(t, new ApiError(0, 'network', 'Backend unreachable'))).toEqual({
      message: 'The backend cannot be reached',
      detail: null,
    });
    expect(describeError(t, new ApiError(403, 'read_only', 'mutations disabled'))).toEqual({
      message: 'Not allowed: the server is read-only',
      detail: 'mutations disabled',
    });
    expect(describeError(t, new ApiError(409, 'busy', 'import running')).message).toBe(
      'Conflict with an operation in progress',
    );
    expect(describeError(t, new ApiError(400, 'bad', 'x')).message).toBe('The request was refused as invalid');
    expect(describeError(t, new ApiError(404, 'nf', 'x')).message).toBe('Not found: it may have been deleted');
    expect(describeError(t, new ApiError(401, 'auth', 'token')).detail).toBeNull();
    expect(describeError(t, new Error('boom'))).toEqual({ message: 'Something went wrong', detail: 'boom' });
  });
});
