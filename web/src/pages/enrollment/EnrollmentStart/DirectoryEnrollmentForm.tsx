import { revalidateLogic } from '@tanstack/react-form';
import type { AxiosError } from 'axios';
import { useState } from 'react';
import z from 'zod';
import { m } from '../../../paraglide/messages';
import { api } from '../../../shared/api/api';
import type { EnrollmentStartResponse } from '../../../shared/api/types';
import { useAppForm } from '../../../shared/form';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';

const formSchema = z.object({
  username: z.string().trim().min(1, m.form_error_required()).max(256),
  password: z.string().min(1, m.form_error_required()).max(1024),
});

type FormFields = z.infer<typeof formSchema>;

const defaultValues: FormFields = {
  username: '',
  password: '',
};

/** The message for a failed directory sign-in; Core never says which part was wrong. */
export const directoryEnrollmentErrorMessage = (status: number | undefined): string => {
  switch (status) {
    case 400:
    case 401:
      return m.enrollment_start_directory_error_invalid();
    case 429:
      return m.enrollment_start_directory_error_throttled();
    default:
      return m.enrollment_start_directory_error_generic();
  }
};

type Props = {
  onStarted: (token: string, enrollment: EnrollmentStartResponse) => void;
};

/**
 * Enrollment with the user's directory (LDAP / Active Directory) credentials. Core checks the
 * password and issues an enrollment token, which then starts enrollment like a typed token.
 */
export const DirectoryEnrollmentForm = ({ onStarted }: Props) => {
  const [error, setError] = useState<string | null>(null);

  const form = useAppForm({
    defaultValues,
    validationLogic: revalidateLogic({
      mode: 'submit',
      modeAfterSubmission: 'change',
    }),
    validators: {
      onDynamic: formSchema,
      onSubmit: formSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      setError(null);
      try {
        const { data } = await api.enrollment.directory.callbackFn({
          data: { username: value.username.trim(), password: value.password },
        });
        const started = await api.enrollment.start.callbackFn({
          data: { token: data.token },
        });
        onStarted(data.token, started.data);
      } catch (e) {
        setError(directoryEnrollmentErrorMessage((e as AxiosError).status));
        // Never keep a rejected password in the form.
        formApi.setFieldValue('password', '');
      }
    },
  });

  return (
    <form.AppForm>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          e.stopPropagation();
          form.handleSubmit();
        }}
      >
        <form.AppField name="username">
          {(field) => (
            <field.FormInput
              required
              label={m.enrollment_start_directory_label_username()}
              autocomplete="username"
            />
          )}
        </form.AppField>
        <SizedBox height={ThemeSpacing.Md} />
        <form.AppField name="password">
          {(field) => (
            <field.FormInput
              required
              type="password"
              label={m.enrollment_start_directory_label_password()}
              autocomplete="current-password"
            />
          )}
        </form.AppField>
        {error && (
          <p className="directory-enrollment-error" role="alert">
            {error}
          </p>
        )}
        <SizedBox height={ThemeSpacing.Md} />
        <form.Subscribe selector={(s) => s.isSubmitting}>
          {(isSubmitting) => (
            <Button
              type="submit"
              text={m.enrollment_start_directory_submit()}
              loading={isSubmitting}
              testId="directory-enrollment-submit"
            />
          )}
        </form.Subscribe>
      </form>
    </form.AppForm>
  );
};
