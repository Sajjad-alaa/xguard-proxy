import { defaultClientDownloadSettings } from '../clientDownloads';

export const openClientLink = (value?: string): void => {
  const href = value ?? defaultClientDownloadSettings.releases_url;
  openVirtualLink(href);
};

export const openVirtualLink = (value: string): void => {
  const anchorElement = document.createElement('a');
  anchorElement.style.display = 'none';
  anchorElement.href = value;
  anchorElement.target = '_blank';
  anchorElement.rel = 'noopener noreferrer';
  document.body.appendChild(anchorElement);
  anchorElement.click();
  anchorElement.remove();
};
