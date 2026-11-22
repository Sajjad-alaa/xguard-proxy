import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../paraglide/messages', () => ({
  m: {
    form_error_required: () => 'required',
    enrollment_start_directory_error_invalid: () => 'invalid',
    enrollment_start_directory_error_throttled: () => 'throttled',
    enrollment_start_directory_error_generic: () => 'generic',
  },
}));
vi.mock('../../../shared/api/api', () => ({ api: {} }));

import { directoryEnrollmentErrorMessage } from './DirectoryEnrollmentForm';

describe('directoryEnrollmentErrorMessage', () => {
  it('never tells which part of the credentials was wrong', () => {
    expect(directoryEnrollmentErrorMessage(401)).toBe('invalid');
    expect(directoryEnrollmentErrorMessage(400)).toBe('invalid');
  });

  it('explains throttling', () => {
    expect(directoryEnrollmentErrorMessage(429)).toBe('throttled');
  });

  it('falls back to a generic message', () => {
    expect(directoryEnrollmentErrorMessage(500)).toBe('generic');
    expect(directoryEnrollmentErrorMessage(undefined)).toBe('generic');
  });
});
