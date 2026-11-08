import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import i18n from '../i18n';
import { describeError } from './errors';

const t = i18n.t.bind(i18n);
const urn = (kind: string) => `urn:netsift:problem:${kind}`;

describe('describeError', () => {
  it('translates common statuses and keeps the raw message as a detail', () => {
    expect(describeError(t, new ApiError(0, 'network', 'Backend unreachable'))).toEqual({
      message: 'The backend cannot be reached',
      detail: null,
    });
    expect(describeError(t, new ApiError(400, urn('bad-request'), 'x')).message).toBe(
      'The request was refused as invalid',
    );
    expect(describeError(t, new ApiError(404, urn('not-found'), 'x')).message).toBe('Not found: it may have been deleted');
    expect(describeError(t, new ApiError(401, urn('unauthorized'), 'token')).detail).toBeNull();
    expect(describeError(t, new ApiError(409, urn('conflict'), 'import running'))).toEqual({
      message: 'Conflict with an operation in progress',
      detail: 'import running',
    });
    expect(describeError(t, new Error('boom'))).toEqual({ message: 'Something went wrong', detail: 'boom' });
  });

  it('tells a read-only server from a path outside the allowed roots', () => {
    expect(describeError(t, new ApiError(403, urn('read-only'), 'Server is read-only')).message).toBe(
      'Not allowed: the server is read-only',
    );
    expect(describeError(t, new ApiError(403, urn('forbidden'), 'path outside the allowed roots'))).toEqual({
      message: 'This path is outside the folders the server is allowed to read',
      detail: 'path outside the allowed roots',
    });
    expect(describeError(t, new ApiError(403, urn('forbidden'), 'cross-site request refused')).message).toBe(
      'Request refused by the server',
    );
  });

  it('has a dedicated message for too many imports', () => {
    expect(describeError(t, new ApiError(409, urn('too-many-imports'), 'Too many imports')).message).toBe(
      'Too many imports running; wait for one of them to finish.',
    );
  });

  it('explains sessions created by another version', () => {
    expect(describeError(t, new ApiError(409, urn('session-too-new'), 'newer'))).toEqual({
      message: 'This session was created by a newer version of NetSift. Update the application to open it.',
      detail: null,
    });
    expect(describeError(t, new ApiError(500, urn('session-upgrade-failed'), 'failed'))).toEqual({
      message:
        'This session could not be upgraded to this version. Check that the data folder is writable, or import the capture again.',
      detail: null,
    });
    expect(describeError(t, new ApiError(500, urn('internal'), 'Internal error')).message).toBe('Something went wrong');
  });
});
