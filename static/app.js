'use strict';
/* ============================================================
   app.js — 入口：视图切换 / 轮询 / 命令面板 / 总控台自身
   ============================================================ */
import { $, el, setText, setChildren, icon, escapeHtml,
  post, act, toast, state, disconnectedText, notifyTaskCompletions,
  applyTheme, initThemeToggle, applyUiTheme,
  currentUiTheme, reconcilePendingUiTheme, trapLayerFocus,
  openLayer, closeLayer, activeLayer,
  currentMutationEpoch, taskNotificationsEnabled, toggleTaskNotifications,
  localServiceUrl, isWindowsPlatform } from './js/core.js';
import { renderLaunchpad, toggleApp, closePortDiagnostic, closeAppDiagnosis } from './js/launchpad.js';
import { renderServices, observePortDiscovery,
  suspendPortDiscovery } from './js/services.js';
import { initWidgets, renderWidgets, openLogsCenter, closeLogsCenter,
  openSettingsCenter, closeSettingsCenter, resetFeedBaseline } from './js/widgets.js';
import { buildGlyphGrid, initAppModal, initLogDrawer, openConfirm,
  openAppModal, closeAppModal, closeConfirm, openLogs, closeLogs,
  openConsoleLog } from './js/overlays.js';
import { configuredPort, actualPorts, portIsOpenable,
  preferredOpenPort } from './js/ports.js';
import { t, getLanguage, setLanguage, subscribeLanguage,
  applyStaticTranslations } from './js/i18n.js';

/* ---------------- DOM 引用 ---------------- */
const banner = $('#banner');
const sideNav = $('#sideNav');
const navBtns = [...sideNav.querySelectorAll('.nav-btn')];
const viewTitle = $('#viewTitle');
const viewOverline = $('#viewOverline');
const viewSub = $('#viewSub');
const navCountLaunch = $('#navCountLaunch'), navCountSvc = $('#navCountSvc');
const sideStats = $('#sideStats');
const languageToggle = $('#languageToggle');
const cmdkTrigger = $('#cmdkTrigger');
const restartConsoleBtn = $('#restartConsoleBtn');
const restartConsoleIcon = $('#restartConsoleIcon');
const restartConsoleLabel = $('#restartConsoleLabel');
const consolePortLabel = $('#consolePortLabel');
const stopConsoleBtn = $('#stopConsoleBtn');
const stopConsoleIcon = $('#stopConsoleIcon');
const stopConsoleLabel = $('#stopConsoleLabel');
const viewLaunchpad = $('#view-launchpad');
const viewServices = $('#view-services');
/* 只有 data-view 的导航轨按钮参与视图切换；data-action 按钮由 widgets 代理 */
const railBtns = [...document.querySelectorAll('.rail-btn[data-view]')];
const sideLaunch = $('#sideLaunch');
const sideSvc = $('#sideSvc');

let firstRender = true;          // 首屏渲染（stagger 入场）
let platformPromise = null;

function syncLanguageToggle() {
  if (!languageToggle) return;
  const language = getLanguage();
  languageToggle.dataset.language = language;
  languageToggle.setAttribute('aria-label', t('language.controlLabel'));
  languageToggle.querySelectorAll('[data-language]').forEach(button => {
    const active = button.dataset.language === language;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
    button.title = t(button.dataset.language === 'en'
      ? 'language.switchToEnglish' : 'language.switchToChinese');
  });
}

function initLanguageToggle() {
  if (!languageToggle) return;
  languageToggle.addEventListener('click', event => {
    const button = event.target.closest('[data-language]');
    if (!button || !languageToggle.contains(button)) return;
    setLanguage(button.dataset.language);
  });
  syncLanguageToggle();
}

function handleLanguageChange() {
  applyStaticTranslations(document);
  syncLanguageToggle();
  applyTheme();
  if (state.platform) applyPlatform(state.platform);
  applyView();
  if (state.data) render();
  if (bannerMessageKey) {
    banner.textContent = t(bannerMessageKey);
  } else if (state.data) {
    setConnected(!banner.classList.contains('disconnected'));
  }
  if (paletteMask && paletteMask.classList.contains('open')) {
    paletteItems = paletteActions();
    renderPalette();
  }
}

function browserPlatformFallback() {
  const reported = String(
    (navigator.userAgentData && navigator.userAgentData.platform)
      || navigator.platform || '',
  ).toLowerCase();
  const os = reported.includes('mac') ? 'darwin'
    : reported.includes('win') ? 'windows' : 'unknown';
  return {
    os,
    arch: '',
    shells: os === 'windows' ? ['auto', 'cmd', 'powershell']
      : os === 'darwin' ? ['posix'] : [],
    packaged: false,
    wslDistros: [],
    degraded: true,
  };
}

function applyPlatform(platform) {
  if (!platform || typeof platform !== 'object' || Array.isArray(platform)) {
    throw new Error(t('errors.platformInvalid'));
  }
  state.platform = platform;
  document.documentElement.dataset.platform = String(platform.os || 'unknown').toLowerCase();
  const windows = isWindowsPlatform(platform);
  const commandShortcut = $('#cmdkShortcut');
  if (commandShortcut) commandShortcut.textContent = windows ? 'Ctrl K' : '⌘K';
  const logsShortcut = $('#logsShortcut');
  if (logsShortcut) logsShortcut.textContent = windows ? 'Ctrl J' : '⌘J';
  const pasteHint = $('#pasteShortcutHint');
  if (pasteHint) pasteHint.textContent = t('appModal.pasteHint', {
    shortcut: windows ? 'Ctrl+V' : '⌘V',
  });
  return platform;
}

/* 平台能力不随 2 秒状态轮询变化，启动时独立读取一次。应用模态会等待
   这份数据再展示 Windows/WSL 控件，macOS 与旧后端均保持原界面。 */
function loadPlatform() {
  if (platformPromise) return platformPromise;
  platformPromise = fetch('/api/platform', { cache: 'no-store' })
    .then(async response => {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const platform = await response.json();
      return applyPlatform(platform);
    })
    .catch(error => {
      /* 旧版 macOS 后端没有此接口。浏览器只用于恢复旧版界面；真正的
         Windows/WSL 破坏性操作仍要求后端签发 instanceKey。 */
      console.warn(t('errors.platformFallback'), error);
      return applyPlatform(browserPlatformFallback());
    });
  return platformPromise;
}

/* ---------------- 视图切换 ---------------- */
function switchView(v) {
  if (state.view === v) return;
  state.view = v;
  localStorage.setItem('console-view', v);
  applyView();
  /* 强制重排以重播视图进入动画 */
  const active = v === 'launchpad' ? viewLaunchpad : viewServices;
  active.classList.remove('active');
  void active.offsetWidth;
  active.classList.add('active');
}
function applyView() {
  const v = state.view;
  navBtns.forEach(b => {
    const active = b.dataset.view === v;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', String(active));
    b.tabIndex = active ? 0 : -1;
  });
  railBtns.forEach(b => {
    const active = b.dataset.view === v;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  sideLaunch.hidden = v !== 'launchpad';
  sideSvc.hidden = v !== 'services';
  viewLaunchpad.classList.toggle('active', v === 'launchpad');
  viewServices.classList.toggle('active', v === 'services');
  viewLaunchpad.setAttribute('aria-hidden', String(v !== 'launchpad'));
  viewServices.setAttribute('aria-hidden', String(v !== 'services'));
  setText(viewTitle, t(v === 'launchpad' ? 'nav.launchpad' : 'nav.services'));
  document.documentElement.dataset.view = v;
  setText(viewOverline, v === 'launchpad' ? 'Launchpad' : 'Services');
  setText(viewSub, t(v === 'launchpad'
    ? 'header.launchpadSubtitle' : 'header.servicesSubtitle'));
}
navBtns.forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
railBtns.forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
sideNav.addEventListener('keydown', e => {
  if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
  e.preventDefault();
  let index = navBtns.indexOf(document.activeElement);
  if (index < 0) return;
  if (e.key === 'Home') index = 0;
  else if (e.key === 'End') index = navBtns.length - 1;
  else index = (index + ((e.key === 'ArrowDown' || e.key === 'ArrowRight') ? 1 : -1) + navBtns.length) % navBtns.length;
  switchView(navBtns[index].dataset.view);
  navBtns[index].focus();
});

/* ============================================================
   轮询
   ============================================================ */
const POLL_INTERVAL_MS = 2000;
const POLL_TIMEOUT_MS = 7000;
let pollPromise = null;
let pollController = null;
let pollTimer = null;
let restartDeadlineTimer = null;
/* 横幅保存语义 key，而不是切换语言前已经翻译好的字符串。这样断线、
   重启和停止中的长驻提示都能随语言切换即时重绘。 */
let bannerMessageKey = '';

function poll(force = false) {
  if (document.hidden && !force) return Promise.resolve();
  if (pollPromise) return pollPromise;
  const controller = new AbortController();
  pollController = controller;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, POLL_TIMEOUT_MS);
  const run = (async () => {
    try {
      const epochAtStart = currentMutationEpoch();
      const r = await fetch('/api/state', {
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!r.ok) {
        const error = new Error('HTTP ' + r.status);
        error.status = r.status;
        throw error;
      }
      const data = await r.json();
      /* 请求发出期间发生了写操作：这份快照是操作生效前的旧状态，
         丢弃并立即补一轮，避免卡片短暂回退到旧状态。 */
      if (epochAtStart !== currentMutationEpoch()) {
        schedulePoll(0);
        return;
      }
      /* 新后端也在状态快照中携带平台信息，使 WSL 安装/删除/启动状态可在
         页面存续期间动态更新；旧后端没有该字段时继续使用启动探测结果。 */
      if (data.platform && typeof data.platform === 'object' && !Array.isArray(data.platform)) {
        applyPlatform(data.platform);
      }
      reconcilePendingUiTheme(data);
      if (state.restartingFrom) {
        suspendPortDiscovery();
        resetFeedBaseline();
      }
      observePortDiscovery(data);
      notifyTaskCompletions(state.data, data);
      state.data = data;
      state.lastUpdate = new Date();
      const restartCompleted = state.restartingFrom && data.consolePid
        && data.consolePid !== state.restartingFrom;
      if (restartCompleted) {
        clearTimeout(restartDeadlineTimer);
        restartDeadlineTimer = null;
        state.restartingFrom = null;
        setConnected(true);
        toast(t('console.restarted'));
      } else if (!state.restartingFrom && !state.stopping) {
        setConnected(true);
      }
      render();
    } catch (e) {
      suspendPortDiscovery();
      resetFeedBaseline();
      if (e && e.name !== 'AbortError') console.error(t('errors.stateRefreshFailed'), e);
      /* 页面进入后台时主动取消请求，不把它误报成断连。 */
      if (!document.hidden || timedOut) {
        const denied = e.status === 401 || e.status === 403;
        setConnected(false, denied ? 'connection.denied' : '');
      }
    } finally {
      clearTimeout(timeout);
      if (pollController === controller) pollController = null;
    }
  })();
  pollPromise = run.finally(() => { pollPromise = null; });
  return pollPromise;
}

function schedulePoll(delay = POLL_INTERVAL_MS) {
  clearTimeout(pollTimer);
  pollTimer = null;
  if (document.hidden) return;
  pollTimer = setTimeout(async () => {
    await poll();
    schedulePoll();
  }, delay);
}

window.__poll = () => poll(true);   // 模块间共享轮询入口
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    suspendPortDiscovery();
    resetFeedBaseline();
    clearTimeout(pollTimer);
    pollTimer = null;
    if (pollController) pollController.abort();
    return;
  }
  poll(true).finally(() => schedulePoll());
});

const HEALTH_COMPONENT_KEYS = {
  services: 'console.component.services',
  watched: 'console.component.watched',
  apps: 'console.component.apps',
  version: 'console.component.version',
  config: 'console.component.config',
};
function stateHealthNotice(data) {
  if (!data) return '';
  const health = data.configHealth || {};
  const messages = [];
  if (data.degraded) {
    const components = [...new Set((data.degradedReasons || [])
      .map(item => t(HEALTH_COMPONENT_KEYS[item && item.component] || 'console.component.partial')))];
    messages.push(t('console.degraded', {
      components: components.length ? components.join(t('common.listSeparator'))
        : t('console.component.partial'),
    }));
  }
  if (health.writable === false) {
    messages.push(t('console.configReadOnly'));
  } else if (health.recoveredFromBackup) {
    messages.push(t('console.configRecovered'));
  }
  if (health.migratedFromSchema != null) {
    messages.push(t('console.configMigrated'));
  }
  return messages.length ? messages.join(t('common.sentenceSeparator')) + t('common.period') : '';
}
function setBannerMessage(key) {
  bannerMessageKey = key || '';
  banner.textContent = bannerMessageKey ? t(bannerMessageKey) : '';
}
function setConnected(ok, messageKey = '') {
  if (!ok) {
    bannerMessageKey = messageKey || 'connection.retrying';
    if (!state.restartingFrom && !state.stopping) {
      banner.textContent = t(bannerMessageKey);
    }
    banner.classList.add('disconnected');
    banner.classList.add('show');
    banner.setAttribute('aria-hidden', 'false');
    return;
  }
  if (state.restartingFrom || state.stopping) return;
  bannerMessageKey = '';
  const notice = stateHealthNotice(state.data);
  banner.textContent = notice || disconnectedText();
  banner.classList.remove('disconnected');
  banner.classList.toggle('show', !!notice);
  banner.setAttribute('aria-hidden', String(!notice));
}
function render() {
  if (!state.data) return;
  const consolePid = Number(state.data.consolePid);
  const restartSupported = Number.isInteger(consolePid) && consolePid > 0;
  setText(consolePortLabel, state.data.consolePort ? ':' + state.data.consolePort : ':----');
  setText(restartConsoleLabel, t(state.restartingFrom
    ? 'common.restarting' : restartSupported ? 'common.restart' : 'common.enable'));
  setText(stopConsoleLabel, t(state.stopping ? 'common.stopping' : 'common.stop'));
  restartConsoleBtn.disabled = !!state.restartingFrom || state.stopping;
  stopConsoleBtn.disabled = !!state.restartingFrom || state.stopping;
  restartConsoleBtn.classList.toggle('needs-activation', !restartSupported);
  restartConsoleBtn.classList.toggle('restarting', !!state.restartingFrom);
  restartConsoleBtn.setAttribute('aria-label', t(restartSupported
    ? 'console.restartAria' : 'console.enableRestartAria'));
  restartConsoleBtn.title = restartSupported
    ? t('console.restartTitle', {
      pid: consolePid,
      port: state.data.consolePort || '----',
    }) +
      (state.data.consoleCwd ? ' · ' + state.data.consoleCwd : '')
    : t('console.legacyTitle');
  /* 侧栏计数：启动台 = 运行中应用数；服务监控 = 我的服务数 */
  const apps = state.data.apps || [];
  const runningApps = apps.filter(a => a.running).length;
  const mineCount = (state.data.services || [])
    .filter(s => s.group === 'mine' && !s.hidden).length;
  setText(navCountLaunch, runningApps ? String(runningApps) : '');
  setText(navCountSvc, mineCount ? String(mineCount) : '');
  setText(sideStats, t('header.sideStats', {
    running: runningApps,
    services: mineCount,
    port: state.data.consolePort || '----',
  }));
  applyUiTheme(currentUiTheme());
  renderLaunchpad(state.data.apps || [], firstRender);
  renderServices(state.data, firstRender);
  renderWidgets(state.data);
  firstRender = false;
}

function showConsoleActivationInfo(action) {
  const recovery = t(isWindowsPlatform()
    ? 'console.activationWindows' : 'console.activationMac');
  openConfirm({
    title: t('console.activationTitle'),
    bodyHtml: t('console.activationBody', {
      console: '<b>' + escapeHtml(consolePortLabel.textContent || t('app.title')) + '</b>',
      action: escapeHtml(action),
    }) + '<div class="confirm-detail">' + recovery + '</div>',
    okText: t('common.know'),
    tone: 'primary',
    onOk: () => {},
  });
}

restartConsoleBtn.addEventListener('click', () => {
  const consolePid = Number(state.data && state.data.consolePid);
  if (state.restartingFrom) return;
  if (!Number.isInteger(consolePid) || consolePid <= 0) {
    showConsoleActivationInfo(t('common.restart'));
    return;
  }
  openConfirm({
    title: t('console.restartConfirmTitle'),
    bodyHtml: t('console.restartConfirmQuestion') +
      '<div class="confirm-detail">' + t('console.restartConfirmDetail') + '</div>',
    okText: t('console.restartNow'),
    tone: 'primary',
    onOk: async () => {
      suspendPortDiscovery();
      state.restartingFrom = consolePid;
      setBannerMessage('console.restartingBanner');
      banner.classList.add('show');
      banner.setAttribute('aria-hidden', 'false');
      render();
      const r = await act(post('/api/console/restart'));
      if (!r || r.ok === false) {
        clearTimeout(restartDeadlineTimer);
        restartDeadlineTimer = null;
        state.restartingFrom = null;
        setConnected(true);
        render();
        return;
      }
      clearTimeout(restartDeadlineTimer);
      restartDeadlineTimer = setTimeout(() => {
        if (!state.restartingFrom) return;
        state.restartingFrom = null;
        setConnected(false, isWindowsPlatform()
          ? 'console.restartTimeoutWindows'
          : 'console.restartTimeoutMac');
        render();
      }, 25000);
    },
  });
});

stopConsoleBtn.addEventListener('click', () => {
  const consolePid = Number(state.data && state.data.consolePid);
  if (state.restartingFrom || state.stopping) return;
  if (!Number.isInteger(consolePid) || consolePid <= 0) {
    showConsoleActivationInfo(t('common.stop'));
    return;
  }
  openConfirm({
    title: t('console.stopConfirmTitle'),
    bodyHtml: t('console.stopConfirmQuestion') +
      '<div class="confirm-detail">' + t('console.stopConfirmDetail') +
      t(isWindowsPlatform() ? 'console.stopAgainWindows' : 'console.stopAgainMac') + '</div>',
    okText: t('console.stopNow'),
    onOk: async () => {
      state.stopping = true;
      setBannerMessage(isWindowsPlatform()
        ? 'console.stoppingWindows' : 'console.stoppingMac');
      banner.classList.add('show');
      banner.setAttribute('aria-hidden', 'false');
      render();
      const r = await act(post('/api/console/stop'));
      if (!r || r.ok === false) {
        state.stopping = false;
        setConnected(true);
        render();
        return;
      }
      setBannerMessage(isWindowsPlatform()
        ? 'console.stoppedWindows' : 'console.stoppedMac');
    },
  });
});

/* ============================================================
   命令面板（⌘K）
   ============================================================ */
const paletteMask = $('#paletteMask'), paletteInput = $('#paletteInput');
const paletteList = $('#paletteList');
let paletteSel = 0;
let paletteItems = [];

function appPortHint(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  if (app && app.running && configured && app.listening === false && actual.length) {
    return ':' + actual[0] + ' (' + t('common.actual') + ')';
  }
  const port = configured || actual[0];
  return port ? ':' + port : t('common.service');
}
/* 与 portIsOpenable 语义一致：仅运行中且确实存在可用端口时可打开。 */
function openableAppPort(app) {
  return app && app.running && portIsOpenable(app)
    ? preferredOpenPort(app) : null;
}

function paletteActions() {
  const items = [
    {
      icon: 'plus',
      title: t('common.addService'),
      hint: t('palette.addServiceHint'),
      run: () => {
        switchView('launchpad');
        openAppModal(null, 'service');
      },
    },
    {
      icon: 'file-text',
      title: t('palette.addTaskTitle'),
      hint: t('palette.addTaskHint'),
      run: () => {
        switchView('launchpad');
        openAppModal(null, 'task');
      },
    },
  ];
  const apps = (state.data && state.data.apps) || [];
  for (const a of apps) {
    const running = !!a.running;
    const isTask = (a.kind || 'service') === 'task';
    const port = openableAppPort(a);
    const name = a.name || t('common.unnamed');
    items.push({
      icon: running ? 'square' : 'play',
      title: t(running
        ? (isTask ? 'palette.abortNamed' : 'palette.stopNamed')
        : (isTask ? 'palette.runNamed' : 'palette.startNamed'), { name }),
      hint: isTask ? t('common.task') : appPortHint(a),
      on: running,
      run: () => toggleApp(a.id),
    });
    if (running && !isTask) {
      items.push({
        icon: 'refresh-cw', title: t('palette.restartNamed', { name }),
        hint: t('common.restart'), on: true,
        run: () => act(post('/api/apps/' + a.id + '/restart', {})),
      });
    }
    if (running && port) {
      items.push({
        icon: 'arrow-up-right', title: t('palette.openNamed', { name }), hint: ':' + port, on: true,
        run: () => window.open(localServiceUrl(a, port), '_blank', 'noopener,noreferrer'),
      });
    }
    items.push({ icon: 'file-text', title: t('palette.viewLogsNamed', { name }),
      hint: t('common.logs'), on: running, run: () => openLogs(a) });
    items.push({ icon: 'pencil', title: t('palette.editNamed', { name }),
      hint: '', on: running, run: () => openAppModal(a) });
  }
  items.push({ icon: 'layout-grid', title: t('palette.switchLaunchpad'),
    hint: t('common.view'), run: () => switchView('launchpad') });
  items.push({ icon: 'activity', title: t('palette.switchServices'),
    hint: t('common.view'), run: () => switchView('services') });
  items.push({
    icon: 'file-text',
    title: t('palette.openLogs'),
    hint: t('common.logs') + ' · ' + (isWindowsPlatform() ? 'Ctrl+J' : '⌘J'),
    run: openLogsCenter,
  });
  items.push({
    icon: 'settings',
    title: t('palette.openSettings'),
    hint: t('palette.settingsHint'),
    run: openSettingsCenter,
  });
  const notifyOn = taskNotificationsEnabled();
  items.push({
    icon: 'clock',
    title: t('palette.notification', {
      state: t(notifyOn ? 'common.enabled' : 'common.disabled'),
    }),
    hint: t('palette.notificationHint'),
    on: notifyOn,
    run: toggleTaskNotifications,
  });
  items.push({
    icon: 'terminal',
    title: t('palette.consoleLogs'),
    hint: t('logs.consoleSubtitle'),
    run: openConsoleLog,
  });
  return items;
}

function paletteFiltered() {
  const q = paletteInput.value.trim().toLowerCase();
  if (!q) return paletteItems;
  return paletteItems.filter(it => (it.title + ' ' + (it.hint || '')).toLowerCase().includes(q));
}

function renderPalette() {
  const items = paletteFiltered();
  paletteSel = Math.max(0, Math.min(paletteSel, items.length - 1));
  paletteList.replaceChildren();
  if (!items.length) {
    const empty = el('div', 'palette-empty');
    empty.textContent = t('palette.noResults');
    paletteList.appendChild(empty);
    paletteInput.removeAttribute('aria-activedescendant');
    return;
  }
  items.forEach((it, i) => {
    const row = el('button', 'pi' + (i === paletteSel ? ' sel' : ''));
    row.type = 'button';
    /* 焦点停留在 combobox，由 aria-activedescendant 表示当前选项。 */
    row.tabIndex = -1;
    row.setAttribute('role', 'option');
    row.id = 'palette-option-' + i;
    row.setAttribute('aria-selected', String(i === paletteSel));
    row.appendChild(el('span', 'pi-dot' + (it.on ? ' on' : '')));
    row.appendChild(icon(it.icon, 15));
    const titleNode = el('span', 'pi-title');
    titleNode.textContent = it.title;
    row.appendChild(titleNode);
    if (it.hint) {
      const h = el('span', 'pi-hint');
      h.textContent = it.hint;
      row.appendChild(h);
    }
    row.addEventListener('click', () => execPalette(it));
    row.addEventListener('mousemove', () => {
      if (paletteSel !== i) { paletteSel = i; syncPaletteSel(); }
    });
    it._row = row;
    paletteList.appendChild(row);
  });
  const selRow = items[paletteSel] && items[paletteSel]._row;
  if (selRow) {
    paletteInput.setAttribute('aria-activedescendant', selRow.id);
    selRow.scrollIntoView({ block: 'nearest' });
  }
}

function syncPaletteSel() {
  const items = paletteFiltered();
  items.forEach((it, i) => {
    if (!it._row) return;
    const selected = i === paletteSel;
    it._row.classList.toggle('sel', selected);
    it._row.setAttribute('aria-selected', String(selected));
  });
  const selected = items[paletteSel] && items[paletteSel]._row;
  if (selected) paletteInput.setAttribute('aria-activedescendant', selected.id);
  else paletteInput.removeAttribute('aria-activedescendant');
}

function openPalette() {
  paletteItems = paletteActions();
  paletteSel = 0;
  paletteInput.value = '';
  renderPalette();
  paletteInput.setAttribute('aria-expanded', 'true');
  openLayer(paletteMask, paletteInput);
}
function closePalette() {
  paletteInput.setAttribute('aria-expanded', 'false');
  paletteInput.removeAttribute('aria-activedescendant');
  closeLayer(paletteMask);
}
function execPalette(it) {
  closePalette();
  Promise.resolve(it.run()).catch(e => toast(t('palette.operationFailed', { message: e.message })));
}

cmdkTrigger.addEventListener('click', openPalette);
paletteInput.addEventListener('input', () => { paletteSel = 0; renderPalette(); });
paletteInput.addEventListener('keydown', e => {
  const items = paletteFiltered();
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    if (!items.length) return;
    paletteSel = (paletteSel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
    syncPaletteSel();
    const row = items[paletteSel] && items[paletteSel]._row;
    if (row) row.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') {
    e.preventDefault();
    const it = items[paletteSel];
    if (it) execPalette(it);
  }
});
paletteMask.addEventListener('mousedown', e => { if (e.target === paletteMask) closePalette(); });

/* ⌘K / Ctrl+K 呼出命令面板 */
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (paletteMask.classList.contains('open')) closePalette();
    else if (!activeLayer()) openPalette();
  }
});
/* ⌘J / Ctrl+J 呼出日志中心（⌘L 是浏览器地址栏保留键，无法拦截） */
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'j') {
    e.preventDefault();
    if ($('#logsMask').classList.contains('open')) closeLogsCenter();
    else if (!activeLayer()) openLogsCenter();
  }
});
window.__openPalette = openPalette;   // hero 卡等跨模块入口

/* Esc 逐层关闭浮层 */
document.addEventListener('keydown', e => {
  trapLayerFocus(e);
  if (e.key === 'Escape') {
    if ($('#confirmMask').classList.contains('open')) closeConfirm();
    else if ($('#logsMask').classList.contains('open')) closeLogsCenter();
    else if ($('#settingsMask').classList.contains('open')) closeSettingsCenter();
    else if ($('#portDiagMask').classList.contains('open')) closePortDiagnostic();
    else if ($('#appDiagMask').classList.contains('open')) closeAppDiagnosis();
    else if ($('#appModalMask').classList.contains('open')) closeAppModal();
    else if (paletteMask.classList.contains('open')) closePalette();
    else if ($('#logDrawer').classList.contains('open')) closeLogs();
  }
});

/* ============================================================
   初始化
   ============================================================ */
applyStaticTranslations(document);
initLanguageToggle();
subscribeLanguage(handleLanguageChange);
setChildren(restartConsoleIcon, icon('refresh-cw', 14));
setChildren(stopConsoleIcon, icon('power', 14));
setChildren($('#githubLink'), icon('github', 15));
setChildren($('#navIconLaunch'), icon('layout-grid', 15));
setChildren($('#navIconSvc'), icon('activity', 15));
setChildren($('#railIconLaunch'), icon('rocket', 19));
setChildren($('#railIconSvc'), icon('activity', 19));
setChildren($('#cmdkIcon'), icon('search', 14));
setChildren($('#paletteIcon'), icon('search', 15));
buildGlyphGrid();
initAppModal({
  onAddService: $('#addSvcCard'),
  onAddTask: $('#addTaskCard'),
  platformReady: loadPlatform(),
});
initLogDrawer();
initThemeToggle();
initWidgets();
applyTheme();
applyUiTheme(currentUiTheme());
applyView();
Promise.all([loadPlatform(), poll(true)]).finally(() => schedulePoll());
