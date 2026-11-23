import './style.scss';

import { useQuery } from '@tanstack/react-query';
import { useLoaderData } from '@tanstack/react-router';
import { capitalCase } from 'change-case';
import { QRCodeCanvas } from 'qrcode.react';
import { useMemo, useState } from 'react';
import { m } from '../../../paraglide/messages';
import {
  buildClientDownloadLinks,
  linuxDownloadItems,
  mobileDownloadItems,
} from '../../../shared/clientDownloads';
import { ContactFooter } from '../../../shared/components/ContactFooter/ContactFooter';
import { ContainerWithIcon } from '../../../shared/components/ContainerWithIcon/ContainerWithIcon';
import { Page } from '../../../shared/components/Page/Page';
import { EnrollmentStep } from '../../../shared/components/Step/Step';
import { getClientDownloadLinksQueryOptions } from '../../../shared/query/queryOptions';
import { openClientLink } from '../../../shared/utils/openVirtualLink';
import { Button } from '../../../shared/xguard-ui/components/Button/Button';
import { CopyField } from '../../../shared/xguard-ui/components/CopyField/CopyField';
import { Divider } from '../../../shared/xguard-ui/components/Divider/Divider';
import { Fold } from '../../../shared/xguard-ui/components/Fold/Fold';
import { Icon } from '../../../shared/xguard-ui/components/Icon';
import { IconButton } from '../../../shared/xguard-ui/components/IconButton/IconButton';
import { IconButtonMenu } from '../../../shared/xguard-ui/components/IconButtonMenu/IconButtonMenu';
import type { MenuItemsGroup } from '../../../shared/xguard-ui/components/Menu/types';
import { SizedBox } from '../../../shared/xguard-ui/components/SizedBox/SizedBox';
import { ThemeSpacing } from '../../../shared/xguard-ui/types';

export const ConfigureClientPage = () => {
  const pageData = useLoaderData({
    from: '/client-setup',
  });

  const { data: fetchedLinks } = useQuery(getClientDownloadLinksQueryOptions);
  const links = fetchedLinks ?? buildClientDownloadLinks();
  const mobileLinks = mobileDownloadItems(links);

  const linuxMenu = useMemo(
    (): MenuItemsGroup[] => [
      {
        header: {
          text: `${capitalCase(m.misc_for())} Linux`,
        },
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

  const [manualOpen, setManualOpen] = useState(false);

  const deepLink = () =>
    `xguard://addinstance?token=${encodeURIComponent(pageData.token)}&url=${encodeURIComponent(pageData.enrollmentData.instance.proxy_url)}`;

  const qrData = () => {
    return btoa(
      JSON.stringify({
        url: pageData.enrollmentData.instance.proxy_url,
        token: pageData.token,
      }),
    );
  };

  return (
    <Page id="configure-client-page">
      {/* Always the final wizard step. */}
      <EnrollmentStep current={2} max={2} />
      <header>
        <h1>{m.client_setup_title()}</h1>
        <p>{m.client_setup_subtitle()}</p>
      </header>
      <SizedBox height={ThemeSpacing.Xl3} />
      <ContainerWithIcon icon="desktop" id="setup-desktop">
        <header>
          <h5>{m.client_setup_desktop_title()}</h5>
          <p>{m.client_setup_desktop_auto_title()}</p>
          <p>
            {m.client_setup_desktop_auto_explain_1()}{' '}
            <span>{m.client_setup_desktop_auto_explain_2()}</span>
          </p>
        </header>
        <div className="buttons">
          <a href={deepLink()} target="_blank" rel="noopener">
            <Button
              text={m.client_setup_desktop_auto_button_one_click()}
              variant="primary"
              iconRight="open-in-new-window"
            />
          </a>
          <div className="download">
            <p>{m.client_setup_download_label()}</p>
            <a
              href={links.windowsX64}
              target="_blank"
              rel="noopener noreferrer"
              title="Windows (x64, .msi)"
              data-testid="download-windows"
            >
              <IconButton icon="windows" />
            </a>
            <a
              href={links.macosUniversal}
              target="_blank"
              rel="noopener noreferrer"
              title="macOS (.dmg)"
              data-testid="download-macos"
            >
              <IconButton icon="apple" />
            </a>
            <IconButtonMenu icon="linux" menuItems={linuxMenu} />
          </div>
        </div>
        <Divider orientation="horizontal" />
        <Fold open={manualOpen} contentClassName="manual">
          <p className="title">{m.client_setup_desktop_manual_title()}</p>
          <p className="subtitle">{m.client_setup_desktop_manual_subtitle()}</p>
          <SizedBox height={ThemeSpacing.Xl2} />
          <div className="form-col-2">
            <CopyField
              text={pageData.enrollmentData.instance.proxy_url}
              copyTooltip={m.cmp_copy_field_tooltip()}
              label={m.form_label_url()}
            />
            <CopyField
              copyTooltip={m.cmp_copy_field_tooltip()}
              text={pageData.token}
              label={m.form_label_token()}
            />
          </div>
          <SizedBox height={ThemeSpacing.Xl2} />
        </Fold>
        <button
          className="fold-button"
          onClick={() => {
            setManualOpen((s) => !s);
          }}
        >
          <Icon icon="config" />
          <span>
            {m.client_setup_desktop_manual_fold({
              intent: manualOpen ? m.controls_hide() : m.controls_show(),
            })}
          </span>
        </button>
      </ContainerWithIcon>
      {pageData.enrollmentData.user.enrolled && (
        <>
          <SizedBox height={ThemeSpacing.Md} />
          <ContainerWithIcon id="setup-mobile" icon="phone">
            <header>
              <h5>{m.client_setup_mobile_title()}</h5>
              <p>{m.client_setup_mobile_subtitle()}</p>
            </header>
            <div className="bottom">
              <div className="qr">
                <QRCodeCanvas value={qrData()} size={100} />
              </div>
              {mobileLinks.length > 0 && (
                <div className="download">
                  <p>{m.client_setup_mobile_forgot()}</p>
                  <div className="links">
                    {mobileLinks.map((item) => (
                      <a
                        key={item.id}
                        href={item.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        data-testid={`download-${item.id}`}
                      >
                        <Button
                          variant="outlined"
                          iconLeft={item.id === 'android' ? 'android' : 'apple'}
                          text={item.label}
                        />
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </ContainerWithIcon>
        </>
      )}
      <footer>
        <p className="finish">{m.client_setup_footer_extra()}</p>
        <ContactFooter email={pageData.enrollmentData.admin.email} />
      </footer>
    </Page>
  );
};
