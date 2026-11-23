import { queryOptions } from '@tanstack/react-query';
import { api } from '../api/api';
import { buildClientDownloadLinks } from '../clientDownloads';

export const getAppInfoQueryOptions = queryOptions({
  queryFn: () => api.appInfo.callbackFn({}),
  queryKey: ['app-info'],
  staleTime: 60 * 1000,
  refetchOnWindowFocus: true,
  refetchOnMount: true,
  refetchOnReconnect: true,
});

/** Download links from the app info, so they come from the Edge and never from a third party. */
export const getClientDownloadLinksQueryOptions = queryOptions({
  ...getAppInfoQueryOptions,
  select: (response) => buildClientDownloadLinks(response.data.client_downloads),
});
