import { useLoaderData, useNavigate } from '@tanstack/react-router';
import { m } from '../../../paraglide/messages';
import { ContainerWithIcon } from '../../../shared/components/ContainerWithIcon/ContainerWithIcon';
import { Page } from '../../../shared/components/Page/Page';
import { PageNavigation } from '../../../shared/components/PageNavigation/PageNavigation';
import { EnrollmentStep } from '../../../shared/components/Step/Step';
import './style.scss';
import { revalidateLogic } from '@tanstack/react-form';
import { useQuery } from '@tanstack/react-query';
import type { AxiosError } from 'axios';
import z from 'zod';
import { api } from '../../../shared/api/api';
import { useAppForm } from '../../../shared/form';
import { useEnrollmentStore } from '../../../shared/hooks/useEnrollmentStore';
import { getAppInfoQueryOptions } from '../../../shared/query/queryOptions';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { ExternalProviderButton } from '../../../shared/xguard-ui/components/ExternalProviderButton/ExternalProviderButton';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';
import { isPresent } from '../../../shared/xguard-ui/utils/isPresent';
import { DirectoryEnrollmentForm } from './DirectoryEnrollmentForm';

const formSchema = z.object({
  token: z.string().trim().min(1, m.form_error_required()),
});

type FormFields = z.infer<typeof formSchema>;

const defaultValues: FormFields = {
  token: '',
};

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

/** Starts a fresh sign-in on click, so it cannot expire while the page stays open. */
const signInWithProvider = async (fallbackUrl: string) => {
  const response = await api.openId.authInfo
    .callbackFn({ data: { type: 'enrollment' } })
    .catch((e: AxiosError) => {
      console.error(e);
    });
  const target = response?.data.url ?? fallbackUrl;
  if (isSafeExternalAuthUrl(target)) {
    window.location.assign(target);
  }
};

export const EnrollmentStartPage = () => {
  const navigate = useNavigate();
  const loaderData = useLoaderData({
    from: '/enrollment-start',
  });
  const setEnrollment = useEnrollmentStore((s) => s.setState);
  const { data: appInfo } = useQuery(getAppInfoQueryOptions);

  const showDownloadStep = appInfo?.data.display_download_step ?? true;
  const showDirectoryEnrollment = appInfo?.data.display_directory_enrollment ?? false;
  const stepMax = showDownloadStep ? 2 : 1;

  const form = useAppForm({
    defaultValues,
    validationLogic: revalidateLogic({
      mode: 'change',
      modeAfterSubmission: 'change',
    }),
    validators: {
      onDynamic: formSchema,
      onSubmit: formSchema,
    },
    onSubmit: async ({ value, formApi }) => {
      const response = await api.enrollment.start
        .callbackFn({
          data: {
            token: value.token,
          },
        })
        .catch((e: AxiosError) => {
          if (e.status === 401) {
            formApi.setErrorMap({
              onSubmit: {
                fields: {
                  token: m.form_error_token(),
                },
              },
            });
          }
        });

      if (!response) {
        return;
      }

      setEnrollment({
        enrollmentData: response.data,
        token: value.token,
      });

      navigate({
        to: showDownloadStep ? '/download' : '/client-setup',
        replace: true,
      });
    },
  });

  return (
    <Page id="enrollment-start-page" nav>
      <EnrollmentStep current={0} max={stepMax} />
      <header>
        <h1>{m.enrollment_start_title()}</h1>
        <p>{m.enrollment_start_subtitle()}</p>
      </header>
      <SizedBox height={ThemeSpacing.Xl3} />
      {isPresent(loaderData?.url) && isSafeExternalAuthUrl(loaderData.url) && (
        <>
          <ContainerWithIcon icon="globe">
            <header>
              <h5>{m.enrollment_start_external_title()}</h5>
              <SizedBox height={ThemeSpacing.Xs} />
              <p>{m.enrollment_start_external_subtitle()}</p>
            </header>
            <div className="openid-link">
              <a
                href={loaderData.url}
                target="_self"
                rel="noopener noreferrer"
                onClick={(e) => {
                  e.preventDefault();
                  void signInWithProvider(loaderData.url as string);
                }}
              >
                <ExternalProviderButton
                  variant="default"
                  provider={loaderData.provider_kind ?? 'custom'}
                  text={
                    loaderData.button_display_name
                      ? m.cmp_openid_button({
                          provider: loaderData.button_display_name,
                        })
                      : 'Sign in with external provider'
                  }
                />
              </a>
            </div>
          </ContainerWithIcon>
          <Divider text={m.misc_or()} orientation="horizontal" />
        </>
      )}
      {showDirectoryEnrollment && (
        <>
          <ContainerWithIcon icon="desktop" id="directory-enrollment">
            <header>
              <h5>{m.enrollment_start_directory_title()}</h5>
              <SizedBox height={ThemeSpacing.Xs} />
              <p>{m.enrollment_start_directory_subtitle()}</p>
            </header>
            <DirectoryEnrollmentForm
              onStarted={(token, enrollmentData) => {
                setEnrollment({ enrollmentData, token });
                navigate({
                  to: showDownloadStep ? '/download' : '/client-setup',
                  replace: true,
                });
              }}
            />
          </ContainerWithIcon>
          <Divider text={m.misc_or()} orientation="horizontal" />
        </>
      )}
      <ContainerWithIcon icon="file">
        <header>
          <h5>{m.enrollment_start_internal_title()}</h5>
          <SizedBox height={ThemeSpacing.Xs} />
          <p>{m.enrollment_start_internal_subtitle()}</p>
        </header>
        <form.AppForm>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              e.stopPropagation();
              form.handleSubmit();
            }}
          >
            <form.AppField name="token">
              {(field) => <field.FormInput required label={m.form_label_token()} />}
            </form.AppField>
          </form>
        </form.AppForm>
      </ContainerWithIcon>
      <PageNavigation
        backText={m.controls_back()}
        onBack={() => {
          navigate({
            to: '/',
            replace: true,
          });
        }}
        nextText={m.controls_continue()}
        onNext={() => {
          form.handleSubmit();
        }}
      />
    </Page>
  );
};
