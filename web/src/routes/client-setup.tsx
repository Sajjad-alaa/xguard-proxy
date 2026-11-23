import { createFileRoute, redirect } from '@tanstack/react-router';
import { ConfigureClientPage } from '../pages/enrollment/ConfigureClient/ConfigureClientPage';
import type { EnrollmentStartResponse } from '../shared/api/types';
import { useEnrollmentStore } from '../shared/hooks/useEnrollmentStore';

export const Route = createFileRoute('/client-setup')({
  component: ConfigureClientPage,
  // check if required session state is present
  beforeLoad: () => {
    const { enrollmentData, token } = useEnrollmentStore.getState();
    if (!enrollmentData || !token) {
      throw redirect({
        to: '/',
        replace: true,
      });
    }
  },
  loader: async () => {
    const state = useEnrollmentStore.getState();
    return {
      token: state.token as string,
      enrollmentData: state.enrollmentData as EnrollmentStartResponse,
    };
  },
});
