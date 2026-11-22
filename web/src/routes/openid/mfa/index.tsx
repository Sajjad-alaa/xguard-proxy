import { createFileRoute, redirect, useLoaderData } from '@tanstack/react-router';
import { useEffect } from 'react';
import z from 'zod';
import { api } from '../../../shared/api/api';
import { isPresent } from '../../../shared/xguard-ui/utils/isPresent';

const isSafeExternalAuthUrl = (rawUrl: string): boolean => {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === 'https:') return true;
    if (parsed.protocol !== 'http:') return false;
    const host = parsed.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
  } catch {
    return false;
  }
};

const searchSchema = z.object({
  token: z.string().trim().min(1),
  step_attempt_id: z.string().trim().min(1).optional(),
});

export const Route = createFileRoute('/openid/mfa/')({
  component: RouteComponent,
  validateSearch: searchSchema,
  onError: () => {
    throw redirect({
      to: '/openid/error',
      replace: true,
    });
  },
  loaderDeps: ({ search }) => ({ search }),
  loader: async ({ deps }) => {
    const response = await api.openId.authInfo
      .callbackFn({
        data: {
          type: 'mfa',
          state: deps.search.step_attempt_id
            ? `${deps.search.token}.${deps.search.step_attempt_id}`
            : deps.search.token,
        },
      })
      .catch((e) => {
        console.error(e);
        throw redirect({
          to: '/openid/error',
          replace: true,
        });
      });
    if (!isPresent(response.data.url) || !isSafeExternalAuthUrl(response.data.url)) {
      console.error('Missing or untrusted URL in server response.');
      throw redirect({
        to: '/openid/error',
        replace: true,
      });
    }
    return response.data.url as string;
  },
});

function RouteComponent() {
  const loaderData = useLoaderData({
    from: '/openid/mfa/',
  });

  useEffect(() => {
    if (loaderData && isSafeExternalAuthUrl(loaderData)) {
      window.location.href = loaderData;
    }
  }, [loaderData]);
  return null;
}
