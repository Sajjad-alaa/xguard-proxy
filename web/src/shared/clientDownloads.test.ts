import { describe, expect, it } from 'vitest';
import {
  assetUrl,
  buildClientDownloadLinks,
  clientAssetNames,
  linuxDownloadItems,
  mobileDownloadItems,
} from './clientDownloads';

const github = 'https://github.com/Sajjad-alaa/xguard-client/releases/latest';

describe('buildClientDownloadLinks', () => {
  it('falls back to the GitHub latest release when Core sent nothing', () => {
    for (const settings of [undefined, null, {}]) {
      expect(buildClientDownloadLinks(settings)).toEqual({
        debAmd64: `${github}/download/xguard-client_amd64.deb`,
        debArm64: `${github}/download/xguard-client_arm64.deb`,
        rpmX86_64: `${github}/download/xguard-client.x86_64.rpm`,
        rpmAarch64: `${github}/download/xguard-client.aarch64.rpm`,
        windowsX64: `${github}/download/xguard-client_x64.msi`,
        macosUniversal: github,
        releases: github,
      });
    }
  });

  it('builds the links from the settings Core sent', () => {
    const links = buildClientDownloadLinks({
      base_url: 'http://10.0.0.5/xguard',
      releases_url: 'http://10.0.0.5/xguard/',
      android_url: 'http://10.0.0.5/xguard/xguard.apk',
      ios_url: null,
      macos_installer: true,
    });
    expect(links.windowsX64).toBe('http://10.0.0.5/xguard/xguard-client_x64.msi');
    expect(links.debArm64).toBe('http://10.0.0.5/xguard/xguard-client_arm64.deb');
    expect(links.macosUniversal).toBe(
      'http://10.0.0.5/xguard/xguard-client_universal.dmg',
    );
    expect(links.releases).toBe('http://10.0.0.5/xguard/');
    expect(mobileDownloadItems(links)).toEqual([
      { id: 'android', label: 'Android', href: 'http://10.0.0.5/xguard/xguard.apk' },
    ]);
  });

  it('ignores links that are not http(s)', () => {
    const links = buildClientDownloadLinks({
      base_url: 'javascript:alert(1)',
      releases_url: 'data:text/html,hi',
      android_url: 'intent://x',
      ios_url: '  ',
    });
    expect(links.windowsX64).toBe(`${github}/download/xguard-client_x64.msi`);
    expect(links.releases).toBe(github);
    expect(links.android).toBeUndefined();
    expect(links.ios).toBeUndefined();
    expect(mobileDownloadItems(links)).toEqual([]);
  });

  it('offers every Linux package', () => {
    const links = buildClientDownloadLinks();
    expect(linuxDownloadItems(links).map((item) => item.href)).toEqual([
      links.debAmd64,
      links.debArm64,
      links.rpmX86_64,
      links.rpmAarch64,
    ]);
    expect(assetUrl('https://a.example/x/', clientAssetNames.windowsX64)).toBe(
      'https://a.example/x/xguard-client_x64.msi',
    );
  });
});
