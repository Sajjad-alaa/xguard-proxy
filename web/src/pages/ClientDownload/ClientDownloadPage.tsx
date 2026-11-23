import './style.scss';
import { useQuery } from '@tanstack/react-query';
import {
  type RouterState,
  useLoaderData,
  useNavigate,
  useRouterState,
} from '@tanstack/react-router';
import { useMemo, useState } from 'react';
import { m } from '../../paraglide/messages';
import {
  buildClientDownloadLinks,
  linuxDownloadItems,
  mobileDownloadItems,
} from '../../shared/clientDownloads';
import { Page } from '../../shared/components/Page/Page';
import { PageNavigation } from '../../shared/components/PageNavigation/PageNavigation';
import { EnrollmentStep } from '../../shared/components/Step/Step';
import { getClientDownloadLinksQueryOptions } from '../../shared/query/queryOptions';
import { openClientLink } from '../../shared/utils/openVirtualLink';
import { Button } from '../../shared/xguard-ui/components/Button/Button';
import { ButtonMenu } from '../../shared/xguard-ui/components/ButtonMenu/MenuButton';
import { Icon } from '../../shared/xguard-ui/components/Icon';
import type { IconKindValue } from '../../shared/xguard-ui/components/Icon/icon-types';
import { InfoBanner } from '../../shared/xguard-ui/components/InfoBanner/InfoBanner';
import type { MenuItemsGroup } from '../../shared/xguard-ui/components/Menu/types';
import { Modal } from '../../shared/xguard-ui/components/Modal/Modal';
import { ModalControls } from '../../shared/xguard-ui/components/ModalControls/ModalControls';
import { SizedBox } from '../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../shared/xguard-ui/types';
import { isPresent } from '../../shared/xguard-ui/utils/isPresent';
import androidIcon from './assets/android.png';
import iosIcon from './assets/ios.png';
import laptopIcon from './assets/laptop.png';
import linuxIcon from './assets/linux.png';
import desktopIcon from './assets/pc-tower.png';

export const ClientDownloadPage = () => {
  const { data: fetchedLinks } = useQuery(getClientDownloadLinksQueryOptions);
  const links = fetchedLinks ?? buildClientDownloadLinks();
  const mobileLinks = mobileDownloadItems(links);
  const { enrollmentState } = useLoaderData({
    from: '/download',
  });
  const routerLoading = useRouterState({ select: (s: RouterState) => s.isLoading });

  const navigate = useNavigate();

  const [confirmModalOpen, setConfirmModalOpen] = useState(false);

  const linuxMenu: MenuItemsGroup[] = useMemo(
    () => [
      {
        items: linuxDownloadItems(links).map((item) => ({
          icon: item.id.startsWith('deb') ? 'ubuntu' : 'linux',
          text: item.label,
          onClick: () => openClientLink(item.href),
        })),
      },
      {
        items: [
          {
            icon: 'linux',
            text: m.client_download_all_downloads(),
            onClick: () => openClientLink(links.releases),
          },
        ],
      },
    ],
    [links],
  );

  return (
    <Page id="client-download-page" nav>
      <EnrollmentStep current={1} max={2} />
      <header>
        <h1>{m.client_download_title()}</h1>
        <p>{m.client_download_subtitle()}</p>
      </header>
      <SizedBox height={ThemeSpacing.Xl3} />
      <div className="platforms">
        <div className="label">
          <Icon icon="desktop" size={20} /> <p>{m.client_download_label_desktop()}</p>
        </div>
        <Platform
          testId="windows"
          title={m.client_download_for({ platform: 'Windows' })}
          subtitle={m.client_download_supports_and({
            platform: 'Windows 10',
            other: 'Windows 11',
          })}
          buttonText={m.client_download_for({ platform: 'Windows' })}
          buttonIconKind="windows"
          directLink={links.windowsX64}
          icon={desktopIcon}
        />
        <Platform
          testId="linux"
          title={m.client_download_for({ platform: 'Linux' })}
          subtitle={m.client_download_supports_linux()}
          buttonText={m.client_download_for({ platform: 'Linux' })}
          buttonIconKind="linux"
          menuItems={linuxMenu}
          icon={linuxIcon}
        />
        <Platform
          testId="macos"
          title={m.client_download_for({ platform: 'MacOS' })}
          subtitle={m.client_download_supports_newer({
            platform: 'macOS 14 (Sonoma)',
          })}
          buttonText={m.client_download_for({ platform: 'Mac' })}
          buttonIconKind="app-store"
          directLink={links.macosUniversal}
          icon={laptopIcon}
        />
      </div>
      <SizedBox height={ThemeSpacing.Xl3} />
      {mobileLinks.length > 0 && enrollmentState.enrollmentData.user.enrolled && (
        <div className="platforms">
          <div className="label">
            <Icon icon="mobile" size={20} /> <p>{m.client_download_label_mobile()}</p>
          </div>
          {links.android && (
            <Platform
              testId="android"
              title={m.client_download_for({ platform: 'Android' })}
              subtitle={m.client_download_supports_newer({
                platform: 'Android 12.0 (Snow Cone)',
              })}
              buttonText={m.client_download_for({ platform: 'Android' })}
              buttonIconKind="android"
              directLink={links.android}
              icon={androidIcon}
            />
          )}
          {links.ios && (
            <Platform
              testId="iOS"
              title={m.client_download_for({ platform: 'iOS' })}
              subtitle={m.client_download_supports_newer({
                platform: 'iOS 15+',
              })}
              buttonText={m.client_download_for({ platform: 'iOS' })}
              buttonIconKind="apple"
              directLink={links.ios}
              icon={iosIcon}
            />
          )}
        </div>
      )}
      {mobileLinks.length > 0 && !enrollmentState.enrollmentData.user.enrolled && (
        <InfoBanner
          variant="warning"
          icon="warning-outlined"
          text={m.client_download_mobile_warning()}
        />
      )}
      <Modal
        title={m.client_download_modal_title()}
        size="small"
        isOpen={confirmModalOpen}
        onClose={
          !routerLoading
            ? () => {
                setConfirmModalOpen(false);
              }
            : undefined
        }
      >
        <p>{m.client_download_modal_content()}</p>
        <ModalControls
          cancelProps={{
            text: m.client_download_modal_cancel(),
            onClick: () => setConfirmModalOpen(false),
            disabled: routerLoading,
          }}
          submitProps={{
            text: m.controls_continue(),
            testId: 'modal-confirm-download-submit',
            loading: routerLoading,
            onClick: () => {
              navigate({
                to: '/client-setup',
                replace: true,
              });
            },
          }}
        />
      </Modal>
      <PageNavigation
        nextText={m.controls_continue()}
        onNext={() => {
          setConfirmModalOpen(true);
        }}
      />
    </Page>
  );
};

const Platform = ({
  buttonIconKind,
  buttonText,
  icon,
  subtitle,
  title,
  testId,
  menuItems,
  directLink,
}: {
  icon: string;
  title: string;
  subtitle: string;
  buttonText: string;
  buttonIconKind: IconKindValue;
  testId: string;
  directLink?: string;
  menuItems?: MenuItemsGroup[];
}) => {
  return (
    <div className="platform" data-testid={testId}>
      <img src={icon} loading="lazy" width={60} height={60} />
      <div className="description">
        <p>{title}</p>
        <p>{subtitle}</p>
      </div>
      {isPresent(directLink) && (
        <a href={directLink} target="_blank" rel="noopener">
          <Button variant="outlined" iconLeft={buttonIconKind} text={buttonText} />
        </a>
      )}
      {isPresent(menuItems) && (
        <ButtonMenu
          variant="outlined"
          menuItems={menuItems}
          iconLeft={buttonIconKind}
          text={buttonText}
        />
      )}
    </div>
  );
};
