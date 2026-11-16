import { get, post } from './api-client';
import type {
  AppInfo,
  EmptyApiResponse,
  EnrollmentStartResponse,
  PasswordResetFinishRequest,
  PasswordResetStartRequest,
  PasswordResetStartResponse,
  TokenRequest,
} from './types';

const api = {
  appInfo: get<AppInfo>('/info'),
  enrollment: {
    start: post<TokenRequest, EnrollmentStartResponse>('/enrollment/start'),
  },
  password: {
    sendEmail: post<PasswordResetStartRequest, EmptyApiResponse>(
      '/password-reset/request',
    ),
    start: post<TokenRequest, PasswordResetStartResponse>('/password-reset/start'),
    finish: post<PasswordResetFinishRequest, EmptyApiResponse>('/password-reset/reset'),
  },
} as const;

export { api };
