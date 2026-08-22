/* i18n.js 纯前端行为测试（node --test，无第三方依赖）。
   锁定语言默认值、持久化、HTML lang、静态翻译、动态插值与订阅契约。
   测试中的 DOM/localStorage 都是最小假对象，语言切换不得访问后端。 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

let importSequence = 0;

function installBrowserFakes(storedLanguage = null) {
  const values = new Map();
  if (storedLanguage !== null) values.set('console-language', storedLanguage);
  const reads = [];
  const writes = [];
  const documentElement = { lang: '', dataset: {} };
  const emptyRoot = { querySelectorAll: () => [] };

  globalThis.localStorage = {
    getItem(key) {
      reads.push(key);
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      writes.push([String(key), String(value)]);
      values.set(String(key), String(value));
    },
    removeItem(key) {
      values.delete(String(key));
    },
  };
  globalThis.document = {
    ...emptyRoot,
    documentElement,
  };
  globalThis.window = globalThis;

  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('i18n must not use fetch');
  };

  return {
    values,
    reads,
    writes,
    documentElement,
    fetchCalls: () => fetchCalls,
  };
}

async function loadI18n(storedLanguage = null) {
  const browser = installBrowserFakes(storedLanguage);
  importSequence += 1;
  const moduleUrl = new URL('../../static/js/i18n.js', import.meta.url);
  moduleUrl.searchParams.set('test', String(importSequence));
  const i18n = await import(moduleUrl.href);
  return { i18n, browser };
}

function flattenStrings(value, prefix = '', output = {}) {
  if (typeof value === 'string') {
    output[prefix] = value;
    return output;
  }
  assert.ok(value && typeof value === 'object' && !Array.isArray(value),
    `translation branch ${prefix || '<root>'} must be an object or string`);
  for (const [key, child] of Object.entries(value)) {
    flattenStrings(child, prefix ? `${prefix}.${key}` : key, output);
  }
  return output;
}

function placeholders(text) {
  return [...String(text).matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)]
    .map(match => match[1])
    .sort();
}

function fakeTextNode(key) {
  const attributes = new Map([['data-i18n', key]]);
  return {
    dataset: { i18n: key },
    textContent: 'UNTRANSLATED',
    getAttribute: name => attributes.get(name) ?? null,
    hasAttribute: name => attributes.has(name),
    setAttribute: (name, value) => attributes.set(name, String(value)),
  };
}

function rootFor(nodes) {
  return {
    querySelectorAll(selector) {
      if (String(selector).includes('[data-i18n]')) return nodes;
      return [];
    },
  };
}

test('translation catalog has identical, non-empty zh and en keys', async () => {
  const { i18n } = await loadI18n();
  assert.ok(i18n.translations, 'i18n.js must export translations');
  assert.ok(i18n.translations.zh, 'translations.zh is required');
  assert.ok(i18n.translations.en, 'translations.en is required');

  const zh = flattenStrings(i18n.translations.zh);
  const en = flattenStrings(i18n.translations.en);
  assert.ok(Object.keys(zh).length >= 20,
    'catalog is unexpectedly small for a whole-app language switch');
  assert.deepEqual(Object.keys(en).sort(), Object.keys(zh).sort());

  for (const key of Object.keys(zh)) {
    assert.ok(zh[key].trim(), `empty zh translation: ${key}`);
    assert.ok(en[key].trim(), `empty en translation: ${key}`);
    assert.deepEqual(placeholders(en[key]), placeholders(zh[key]),
      `placeholder mismatch: ${key}`);
    const englishUiText = (key === 'language.chinese' ? '' : en[key])
      .replaceAll('总控台.app', '')
      .replaceAll('总控台.exe', '')
      .replaceAll('%LOCALAPPDATA%\\总控台', '');
    assert.doesNotMatch(englishUiText, /[\u3400-\u9fff]/u,
      `English translation still contains Chinese UI text: ${key}`);
  }
});

test('every static data-i18n key exists in both catalogs', async () => {
  const { i18n } = await loadI18n();
  const zh = flattenStrings(i18n.translations.zh);
  const en = flattenStrings(i18n.translations.en);
  const htmlPath = new URL('../../static/index.html', import.meta.url);
  const html = await readFile(htmlPath, 'utf8');
  const keys = [...html.matchAll(
    /\bdata-i18n(?:-[a-z-]+)?=["']([^"']+)["']/giu,
  )].map(match => match[1]);

  assert.ok(new Set(keys).size >= 50,
    'index.html is missing whole-page data-i18n coverage');
  for (const key of new Set(keys)) {
    assert.ok(Object.hasOwn(zh, key), `missing zh key used by HTML: ${key}`);
    assert.ok(Object.hasOwn(en, key), `missing en key used by HTML: ${key}`);
  }
});

test('Chinese is the default and invalid stored values safely fall back to it', async () => {
  for (const stored of [null, '', 'fr', 'EN', 'zh-CN']) {
    const { i18n, browser } = await loadI18n(stored);
    assert.equal(i18n.getLanguage(), 'zh');
    assert.equal(browser.documentElement.lang, 'zh-CN');
    assert.equal(browser.fetchCalls(), 0);
  }
});

test('stored English is restored and updates the root HTML language', async () => {
  const { i18n, browser } = await loadI18n('en');
  assert.equal(i18n.getLanguage(), 'en');
  assert.equal(browser.documentElement.lang, 'en');
  assert.equal(browser.fetchCalls(), 0);
});

test('setLanguage and toggleLanguage only persist console-language', async () => {
  const { i18n, browser } = await loadI18n();

  i18n.setLanguage('en');
  assert.equal(i18n.getLanguage(), 'en');
  assert.equal(browser.documentElement.lang, 'en');
  assert.deepEqual(browser.writes, [['console-language', 'en']]);

  const toggled = i18n.toggleLanguage();
  assert.equal(toggled, 'zh');
  assert.equal(i18n.getLanguage(), 'zh');
  assert.equal(browser.documentElement.lang, 'zh-CN');
  assert.deepEqual(browser.writes, [
    ['console-language', 'en'],
    ['console-language', 'zh'],
  ]);
  assert.equal(browser.fetchCalls(), 0);
});

test('language subscribers are notified and can unsubscribe', async () => {
  const { i18n } = await loadI18n();
  const observed = [];
  const unsubscribe = i18n.subscribeLanguage(language => observed.push(language));
  assert.equal(typeof unsubscribe, 'function');

  i18n.setLanguage('en');
  assert.deepEqual(observed, ['en']);
  unsubscribe();
  i18n.setLanguage('zh');
  assert.deepEqual(observed, ['en']);
});

test('t translates dynamic strings and interpolates named placeholders', async () => {
  const { i18n } = await loadI18n();
  const zh = flattenStrings(i18n.translations.zh);
  const interpolationEntry = Object.entries(zh)
    .find(([, value]) => placeholders(value).length > 0);
  assert.ok(interpolationEntry,
    'catalog needs at least one dynamic string with a {name} placeholder');

  const [key, template] = interpolationEntry;
  const params = Object.fromEntries(placeholders(template)
    .map(name => [name, `VALUE_${name}`]));
  const translatedZh = i18n.t(key, params);
  for (const replacement of Object.values(params)) {
    assert.ok(translatedZh.includes(replacement),
      `missing interpolation value in ${key}`);
  }

  i18n.setLanguage('en');
  const translatedEn = i18n.t(key, params);
  for (const replacement of Object.values(params)) {
    assert.ok(translatedEn.includes(replacement),
      `missing English interpolation value in ${key}`);
  }
  assert.notEqual(translatedEn, translatedZh,
    `dynamic translation did not change for ${key}`);
});

test('applyStaticTranslations translates data-i18n text in both languages', async () => {
  const { i18n } = await loadI18n();
  const zh = flattenStrings(i18n.translations.zh);
  const staticEntry = Object.entries(zh)
    .find(([, value]) => placeholders(value).length === 0);
  assert.ok(staticEntry, 'catalog needs at least one non-interpolated static string');

  const [key] = staticEntry;
  const node = fakeTextNode(key);
  const root = rootFor([node]);

  i18n.applyStaticTranslations(root);
  assert.equal(node.textContent, i18n.t(key));

  i18n.setLanguage('en');
  i18n.applyStaticTranslations(root);
  assert.equal(node.textContent, i18n.t(key));
});

test('dynamic server labels translate without changing user-provided values', async () => {
  const { i18n } = await loadI18n();
  assert.equal(i18n.translateKnownText('系统'), '系统');
  const chineseHealth = '找不到配置的工作目录：C:\\work\\demo';
  assert.equal(i18n.translateKnownText(chineseHealth), chineseHealth);
  i18n.setLanguage('en');

  assert.equal(i18n.translateKnownText('系统'), 'System');
  assert.equal(i18n.translateKnownText('总控台'), 'Console');
  assert.equal(i18n.translateKnownText('终端'), 'Terminal');
  assert.equal(
    i18n.translateKnownText('Ubuntu · 总控台'),
    'Ubuntu · Console',
  );
  assert.equal(
    i18n.translateKnownText('UNC 路径属于另一个 WSL 发行版'),
    'The UNC path belongs to a different WSL distribution',
  );
  const discoveryOutput = 'wsl.exe: access denied';
  assert.equal(
    i18n.translateKnownText(`WSL 发行版枚举失败: ${discoveryOutput}`),
    `WSL distribution discovery failed: ${discoveryOutput}`,
  );

  const healthPath = 'C:\\work\\中文项目';
  assert.equal(
    i18n.translateKnownText(`找不到配置的工作目录：${healthPath}`),
    `Configured working directory not found: ${healthPath}`,
  );
  const distro = '开发环境';
  assert.equal(
    i18n.translateKnownText(`WSL1 不受支持；请运行 wsl --set-version ${distro} 2`),
    `WSL1 is unsupported. Run: wsl --set-version ${distro} 2`,
  );

  const packageName = '用户自定义包';
  assert.equal(
    i18n.translateKnownText(`缺少 Python 包：${packageName}`),
    `Missing Python package: ${packageName}`,
  );
  const runtimeName = '用户自定义 运行时';
  assert.equal(
    i18n.translateKnownText(`找不到 ${runtimeName}`),
    `${runtimeName} not found`,
  );
  const installPath = 'C:\\workspace\\中文项目';
  assert.equal(
    i18n.translateKnownText(
      `终端执行：cd "${installPath}" && pnpm install，装完再启动。`,
    ),
    `Run in a terminal: cd "${installPath}" && pnpm install, then start the app again.`,
  );
  assert.equal(
    i18n.translateKnownText(
      '终端执行：cd "<项目目录>" && npm install（仍报错再 rm -rf node_modules 后重装）。',
    ),
    'Run in a terminal: cd "<project-directory>" && npm install. '
      + 'If it still fails, remove node_modules and reinstall.',
  );
  assert.equal(
    i18n.translateKnownText(
      '日志报 missing script。package.json 里可用的脚本：dev、中文脚本。',
    ),
    'The log reports "missing script". Available scripts in package.json: '
      + 'dev, 中文脚本.',
  );

  for (const userValue of [
    'my-service',
    'npm run dev',
    'C:\\workspace\\中文项目',
    '[stderr] 用户自定义日志',
  ]) {
    assert.equal(i18n.translateKnownText(userValue), userValue);
  }
});

test('common operation errors translate while dynamic data stays intact', async () => {
  const { i18n } = await loadI18n('en');

  const exactCases = new Map([
    ['进程身份已失效，请刷新后重试',
      'The process identity is no longer valid. Refresh and try again.'],
    ['外部 Windows 进程无法证明安全的优雅停止；请确认后强制结束',
      'A safe graceful stop cannot be proven for this external Windows process. '
        + 'Confirm before force ending it.'],
    ['该进程已由其他卡片管理',
      'This process is already managed by another card'],
    ['该应用正在执行其他操作，请稍后重试',
      'Another operation is already in progress for this application. Try again shortly.'],
    ['图标大小不能超过 5MB', 'The icon cannot exceed 5 MB'],
    ['没有可更新的字段', 'There are no fields to update'],
  ]);
  for (const [source, expected] of exactCases) {
    assert.equal(i18n.translateKnownText(source), expected);
  }

  const osError = 'CreateProcess error=2';
  assert.equal(
    i18n.translateKnownText(`启动失败: ${osError}`),
    `Startup failed: ${osError}`,
  );
  const logLine = '用户脚本输出：配置不存在';
  assert.equal(
    i18n.translateKnownText(`启动命令立即退出（exit 1）：${logLine}`),
    `The start command exited immediately (exit 1): ${logLine}`,
  );
  const appName = '我的服务';
  assert.equal(
    i18n.translateKnownText(`该进程已由卡片「${appName}」管理`),
    `This process is already managed by the card "${appName}"`,
  );
  assert.equal(
    i18n.translateKnownText('端口 3000 已被 Windows PID 42 占用'),
    'Port 3000 is occupied by Windows PID 42',
  );
  assert.equal(
    i18n.translateKnownText('应用正在运行，请先在当前编辑面板停止服务；填写内容会保留'),
    'The application is running. Use "Stop service" in this editor first; '
      + 'your entries will be preserved.',
  );
  assert.equal(
    i18n.translateKnownText('删除已取消：应用未能正常退出'),
    'Deletion canceled: The application did not exit normally',
  );
});

test('service origins render through the known-label translator', async () => {
  const servicesPath = new URL('../../static/js/services.js', import.meta.url);
  const source = await readFile(servicesPath, 'utf8');
  assert.match(source,
    /import\s*\{[^}]*\btranslateKnownText\b[^}]*\}\s*from\s*['"]\.\/i18n\.js['"]/s);
  assert.match(source,
    /const\s+originLabel\s*=\s*translateKnownText\(origin\.label\)/);
  assert.match(source,
    /services\.startedBy['"],\s*\{\s*origin:\s*originLabel\s*\}/s);
  assert.match(source,
    /setText\(r\.subText,[\s\S]*?originLabel\)/);
});

test('port title interpolation uses the caller-facing all placeholder', async () => {
  const { i18n } = await loadI18n('en');
  const title = i18n.t('launchpad.portOpenTitle', {
    url: 'http://localhost:3000',
    all: ' (all: 3000, 3001)',
  });
  assert.equal(title, 'Open http://localhost:3000 (all: 3000, 3001)');
  assert.doesNotMatch(title, /\{[^}]+\}/);
});

test('static paste hint has no unresolved platform shortcut placeholder', async () => {
  const { i18n } = await loadI18n();
  assert.doesNotMatch(i18n.t('appearance.pasteHint'), /\{shortcut\}/);
  i18n.setLanguage('en');
  assert.doesNotMatch(i18n.t('appearance.pasteHint'), /\{shortcut\}/);
});
