'use strict';
/* ============================================================
   widgets.js — 右侧信息栏与导航轨
   实时动态/实时告警（会话内状态差异事件流，首帧静默建立基线）、
   端口/资源 TOP 5、小贴士、快捷操作、导航轨连接状态与版本。
   全部数据来自 /api/state 轮询快照，不新增后端接口。
   ============================================================ */
import { $, el, setText, setChildren, icon, state, fmtClock, taskExitStatus,
  openLayer, closeLayer, toast, escapeHtml, applyTheme,
  taskNotificationsEnabled, toggleTaskNotifications, isWindowsPlatform } from './core.js';
import { openAppModal, openLogs, openConsoleLog, openConfirm,
  requestManagedAppStop } from './overlays.js';
import { configuredPort } from './ports.js';
import { t } from './i18n.js';

const FEED_CAP = 50;
let feedSeq = 0;
let feedEvents = [];
let prevSnap = null;              // 上一份用于差异对比的快照

/* 断线、页面转入后台或总控台重启后由 app.js 调用：
   丢弃旧基线，下一份快照只重建基线，避免把断档期积压的变化
   一次性当作“刚刚发生”的事件灌进实时动态/告警。 */
export function resetFeedBaseline() {
  prevSnap = null;
}

const feedListL = $('#feedListL'), feedListS = $('#feedListS');
const topPortsL = $('#topPortsL'), topPortsS = $('#topPortsS');
const topResS = $('#topResS'), resTabs = $('#resTabs');
const tipsText = $('#tipsText'), tipsAction = $('#tipsAction');
const railConnDot = $('#railConnDot'), railConnText = $('#railConnText');
const railVer = $('#railVer');
let resMetric = 'cpu';

function syncConnectionLabel() {
  const banner = $('#banner');
  const down = banner.classList.contains('disconnected');
  railConnDot.classList.toggle('running', !down);
  railConnDot.classList.toggle('danger', down);
  setText(railConnText, t(down ? 'connection.disconnected' : 'connection.connected'));
}

/* ---------------- 静态装饰图标与快捷操作 ---------------- */
export function initWidgets() {
  document.querySelectorAll('[data-ov-icon]').forEach(node => {
    setChildren(node, icon(node.dataset.ovIcon, 17));
  });
  document.querySelectorAll('[data-qa-icon]').forEach(node => {
    setChildren(node, icon(node.dataset.qaIcon, 13));
  });
  setChildren($('#tipsIcon'), icon('brain', 14));

  /* 顶栏与侧栏的快捷操作统一走 data-qa 代理 */
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-qa]');
    if (!btn) return;
    const action = btn.dataset.qa;
    if (action === 'add-svc') openAppModal(null, 'service');
    else if (action === 'add-task') openAppModal(null, 'task');
    else if (action === 'refresh' && window.__poll) window.__poll();
    else if (action === 'logs') openLogsCenter();
    else if (action === 'settings') openSettingsCenter();
    else if (action === 'batch-stop') batchStopApps();
  });
  /* 导航轨动作按钮（非视图切换） */
  document.querySelectorAll('.rail-btn[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.action === 'logs') openLogsCenter();
      else if (btn.dataset.action === 'settings') openSettingsCenter();
    });
  });
  setChildren($('#railIconLogs'), icon('file-text', 19));
  setChildren($('#railIconSettings'), icon('settings', 19));
  $('#logsMaskClose').addEventListener('click', closeLogsCenter);
  $('#logsMask').addEventListener('mousedown', e => {
    if (e.target === $('#logsMask')) closeLogsCenter();
  });
  $('#settingsMaskClose').addEventListener('click', closeSettingsCenter);
  $('#settingsMask').addEventListener('mousedown', e => {
    if (e.target === $('#settingsMask')) closeSettingsCenter();
  });
  $('#setNotify').addEventListener('click', () => {
    toggleTaskNotifications();
    syncSettings();
  });
  $('#setAppearance').addEventListener('click', e => {
    const tab = e.target.closest('.mini-tab');
    if (!tab) return;
    const mode = tab.dataset.appearance;
    if (mode === 'auto') localStorage.removeItem('console-theme');
    else localStorage.setItem('console-theme', mode);
    applyTheme();
    syncSettings();
  });

  $('#feedClearL').addEventListener('click', clearFeed);
  $('#feedClearS').addEventListener('click', clearFeed);
  resTabs.addEventListener('click', e => {
    const tab = e.target.closest('.mini-tab');
    if (!tab) return;
    resMetric = tab.dataset.metric === 'mem' ? 'mem' : 'cpu';
    for (const metricTab of resTabs.querySelectorAll('.mini-tab')) {
      metricTab.classList.toggle('active', metricTab === tab);
    }
    if (state.data) renderTopRes(state.data);
  });

  /* 横幅也承载“已连接但降级”等提示，只有 disconnected 才是断线。 */
  const banner = $('#banner');
  new MutationObserver(syncConnectionLabel)
    .observe(banner, { attributes: true, attributeFilter: ['class'] });
  syncConnectionLabel();

  tipsAction.addEventListener('click', () => {
    const tab = $('#tab-services');
    if (tab) tab.click();
  });
}

/* ---------------- 实时动态 / 实时告警 ----------------
   对比相邻两份轮询快照产生事件；首份快照只建立基线，
   断线/后台恢复后同样静默重建，避免把存量当新闻。 */
function snapshotMaps(data) {
  const apps = new Map();
  for (const a of data.apps || []) {
    apps.set(a.id, {
      name: a.name || '',
      kind: a.kind || 'service',
      running: !!a.running,
      port: configuredPort(a),
      occupied: !!a.portOccupied,
      exitAt: a.lastExit && a.lastExit.at ? a.lastExit.at : 0,
      exit: a.lastExit || null,
    });
  }
  const services = new Map();
  for (const s of data.services || []) {
    const key = s.instanceKey || s.key;
    if (!key) continue;
    services.set(key, {
      name: s.appName || s.project || s.name || '',
      port: s.port,
      mine: s.group === 'mine' && !s.hidden,
      linked: !!s.appId,   // 已关联启动台卡片的服务由应用事件覆盖，不重复上报
    });
  }
  return { apps, services, degraded: !!data.degraded };
}

function pushEvent(level, titleKey, titleVars = {}, subKey = '', subVars = {}) {
  feedEvents.unshift({
    seq: ++feedSeq,
    at: new Date(),
    level,
    titleKey,
    titleVars,
    subKey,
    subVars,
  });
  if (feedEvents.length > FEED_CAP) feedEvents.length = FEED_CAP;
}

function diffSnapshot(prev, next) {
  for (const [id, app] of next.apps) {
    const before = prev.apps.get(id);
    if (!before) continue;    // 新建卡片不算动态
    if (!before.running && app.running) {
      pushEvent('info', app.kind === 'task'
        ? 'widgets.event.taskStarted' : 'widgets.event.serviceStarted', { name: app.name },
      app.port ? 'widgets.event.port' : '', { port: app.port });
    } else if (before.running && !app.running) {
      pushEvent('info', app.kind === 'task'
        ? 'widgets.event.taskEnded' : 'widgets.event.serviceStopped', { name: app.name },
      app.port ? 'widgets.event.port' : '', { port: app.port });
    }
    if (!before.occupied && app.occupied) {
      pushEvent('warn', 'widgets.event.portConflict', {}, 'widgets.event.portOccupied', {
        name: app.name,
        port: app.port || '',
      });
    }
    if (app.exitAt && app.exitAt !== before.exitAt && app.exit) {
      const status = taskExitStatus(app.exit);
      if (app.kind === 'task') {
        if (status === 'succeeded') {
          pushEvent('ok', 'widgets.event.taskSucceeded', { name: app.name });
        }
        else if (status === 'failed') {
          pushEvent('error', 'widgets.event.taskFailed', { name: app.name },
            app.exit.code != null ? 'common.exitCode' : '', { code: app.exit.code });
        } else if (status === 'canceled') {
          pushEvent('warn', 'widgets.event.taskCanceled', { name: app.name });
        } else {
          pushEvent('warn', 'widgets.event.taskAborted', { name: app.name });
        }
      } else if (app.exit.code) {
        pushEvent('error', 'widgets.event.appExited', { name: app.name },
          'common.exitCode', { code: app.exit.code });
      }
    }
  }
  for (const [key, svc] of next.services) {
    if (!prev.services.has(key) && svc.mine && !svc.linked) {
      pushEvent('info', 'widgets.event.serviceStarted', { name: svc.name },
        svc.port ? 'widgets.event.port' : '', { port: svc.port });
    }
  }
  for (const [key, svc] of prev.services) {
    if (!next.services.has(key) && svc.mine && !svc.linked) {
      pushEvent('info', 'widgets.event.serviceStopped', { name: svc.name },
        svc.port ? 'widgets.event.port' : '', { port: svc.port });
    }
  }
  if (!prev.degraded && next.degraded) {
    pushEvent('error', 'widgets.event.degraded', {}, 'widgets.event.incomplete');
  }
}

function feedItem(ev) {
  const item = el('div', 'feed-item');
  const dot = el('span', 'feed-dot lvl-' + ev.level);
  dot.setAttribute('aria-hidden', 'true');
  const main = el('div', 'feed-main');
  const title = el('div', 'feed-title');
  const titleVars = { ...ev.titleVars };
  if (Object.hasOwn(titleVars, 'name') && !titleVars.name) {
    titleVars.name = t(ev.titleKey.includes('service')
      ? 'common.localService' : 'common.unnamed');
  }
  title.textContent = t(ev.titleKey, titleVars);
  main.appendChild(title);
  if (ev.subKey) {
    const sub = el('div', 'feed-sub');
    const subVars = { ...ev.subVars };
    if (Object.hasOwn(subVars, 'name') && !subVars.name) {
      subVars.name = t('common.unnamed');
    }
    sub.textContent = t(ev.subKey, subVars);
    main.appendChild(sub);
  }
  const time = el('span', 'feed-time mono');
  time.textContent = fmtClock(ev.at).slice(0, 5);
  item.append(dot, main, time);
  return item;
}

function renderFeedInto(list, events, emptyKey) {
  list.replaceChildren();
  if (!events.length) {
    const empty = el('div', 'feed-empty');
    empty.textContent = t(emptyKey);
    list.appendChild(empty);
    return;
  }
  for (const ev of events.slice(0, 12)) list.appendChild(feedItem(ev));
}

function renderFeeds() {
  renderFeedInto(feedListL, feedEvents, 'widgets.emptyActivity');
  renderFeedInto(feedListS,
    feedEvents.filter(ev => ev.level === 'warn' || ev.level === 'error'),
    'widgets.emptyAlerts');
}

function clearFeed() {
  feedEvents = [];
  renderFeeds();
}

/* ---------------- TOP 5 ---------------- */
function mineServices(data) {
  return (data.services || []).filter(s => s.group === 'mine' && !s.hidden);
}

function renderTopPortsInto(container, data) {
  const apps = data.apps || [];
  const rows = mineServices(data)
    .filter(s => Number.isInteger(s.port))
    .sort((a, b) => a.port - b.port)
    .slice(0, 5);
  container.replaceChildren();
  if (!rows.length) {
    const empty = el('div', 't5-empty');
    empty.textContent = t('widgets.noPorts');
    container.appendChild(empty);
    return;
  }
  rows.forEach((svc, i) => {
    const row = el('div', 't5-row');
    const rank = el('span', 't5-rank');
    rank.textContent = String(i + 1);
    const port = el('span', 't5-port');
    port.textContent = ':' + svc.port;
    const name = el('span', 't5-name');
    name.textContent = svc.appName || svc.project || svc.name || t('common.localService');
    name.title = name.textContent;
    row.append(rank, port, name);
    const conflict = apps.some(a => a.portOccupied && configuredPort(a) === svc.port);
    if (conflict) {
      const tag = el('span', 't5-tag');
      tag.textContent = t('widgets.conflict');
      row.appendChild(tag);
    }
    container.appendChild(row);
  });
}

function renderTopRes(data) {
  const rows = mineServices(data)
    .slice()
    .sort((a, b) => (b[resMetric] || 0) - (a[resMetric] || 0))
    .slice(0, 5);
  topResS.replaceChildren();
  if (!rows.length) {
    const empty = el('div', 't5-empty');
    empty.textContent = t('widgets.noProcesses');
    topResS.appendChild(empty);
    return;
  }
  rows.forEach((svc, i) => {
    const row = el('div', 't5-row');
    const rank = el('span', 't5-rank');
    rank.textContent = String(i + 1);
    const name = el('span', 't5-name');
    name.textContent = svc.appName || svc.project || svc.name || t('common.localService');
    name.title = name.textContent;
    const val = el('span', 't5-val');
    const pct = typeof svc[resMetric] === 'number' ? svc[resMetric] : 0;
    val.textContent = pct.toFixed(1) + '%';
    const bar = el('span', 't5-bar');
    const fill = el('i');
    fill.style.width = Math.max(2, Math.min(100, pct)) + '%';
    bar.appendChild(fill);
    row.append(rank, name, bar, val);
    topResS.appendChild(row);
  });
}

/* ---------------- 小贴士 ---------------- */
function renderTips(data) {
  const conflicts = (data.apps || []).filter(a => a.portOccupied).length;
  let text;
  let actionable = false;
  if (conflicts > 0) {
    text = t('widgets.tipConflicts', { count: conflicts });
    actionable = true;
  } else if (data.degraded) {
    text = t('widgets.tipDegraded');
  } else {
    text = t('widgets.tipHealthy', {
      shortcut: isWindowsPlatform() ? 'Ctrl+K' : '⌘K',
    });
  }
  setText(tipsText, text);
  tipsAction.hidden = !actionable;
}

/* ---------------- 主入口（每轮轮询调用） ---------------- */
export function renderWidgets(data) {
  if (!data) return;
  syncConnectionLabel();
  const next = snapshotMaps(data);
  if (prevSnap) diffSnapshot(prevSnap, next);
  prevSnap = next;
  renderFeeds();
  renderTopPortsInto(topPortsL, data);
  renderTopPortsInto(topPortsS, data);
  renderTopRes(data);
  renderTips(data);
  setText(railVer, data.version ? 'v' + data.version : 'v—');
  /* 语言切换会用当前快照重走 renderWidgets；同步重绘已经打开的动态弹层，
     避免日志行状态等仍停留在切换前的语言。 */
  if (logsMask.classList.contains('open')) renderLogsList();
  if (settingsMask.classList.contains('open')) syncSettings();
}

/* ============================================================
   日志中心（聚合弹层，⌘J）：所有应用与总控台日志的目录页
   ============================================================ */
const logsMask = $('#logsMask'), logsList = $('#logsList');

function logsRow(app) {
  const row = el('button', 'logs-item');
  row.type = 'button';
  const box = el('span', 'logs-ic');
  if (app.icon) {
    const img = new Image();
    img.src = app.icon;
    img.alt = '';
    box.appendChild(img);
  } else if (app.glyph && window.LUCIDE && window.LUCIDE[app.glyph]) {
    box.appendChild(icon(app.glyph, 14));
  } else {
    box.textContent = app.name ? [...app.name][0].toUpperCase() : '?';
  }
  const main = el('span', 'logs-main');
  const name = el('span', 'logs-name');
  name.textContent = app.name || t('common.unnamed');
  const sub = el('span', 'logs-sub');
  const isTask = (app.kind || 'service') === 'task';
  const port = configuredPort(app);
  const status = t(app.running ? 'common.running' : 'common.stopped');
  sub.textContent = isTask ? t('logs.appSubtitleTask', { status })
    : port ? t('logs.appSubtitlePort', { status, port }) : status;
  main.append(name, sub);
  row.append(box, main, icon('chevron-right', 14));
  row.addEventListener('click', () => {
    closeLogsCenter();
    openLogs(app);
  });
  return row;
}

function renderLogsList() {
  logsList.replaceChildren();
  const apps = (state.data && state.data.apps) || [];
  const sorted = apps.slice().sort((a, b) => (!!b.running) - (!!a.running));
  for (const app of sorted) logsList.appendChild(logsRow(app));
  /* 总控台自身日志固定在最后 */
  const row = el('button', 'logs-item');
  row.type = 'button';
  const box = el('span', 'logs-ic');
  box.appendChild(icon('terminal', 14));
  const main = el('span', 'logs-main');
  const name = el('span', 'logs-name');
  name.textContent = t('logs.console');
  const sub = el('span', 'logs-sub');
  sub.textContent = t('logs.consoleSubtitle');
  main.append(name, sub);
  row.append(box, main, icon('chevron-right', 14));
  row.addEventListener('click', () => {
    closeLogsCenter();
    openConsoleLog();
  });
  logsList.appendChild(row);
  if (!apps.length) {
    const empty = el('div', 'logs-empty');
    empty.textContent = t('logs.empty');
    logsList.prepend(empty);
  }
}

export function openLogsCenter() {
  renderLogsList();
  openLayer(logsMask, $('#logsMaskClose'));
}
export function closeLogsCenter() { closeLayer(logsMask); }

/* ============================================================
   设置中心（聚合弹层）：通知开关 / 外观 / 版本与目录信息
   ============================================================ */
const settingsMask = $('#settingsMask');

function syncSettings() {
  const on = taskNotificationsEnabled();
  const sw = $('#setNotify');
  sw.classList.toggle('on', on);
  sw.setAttribute('aria-checked', String(on));
  const stored = localStorage.getItem('console-theme');
  const mode = stored === 'dark' ? 'dark' : stored === 'light' ? 'light' : 'auto';
  for (const tab of $('#setAppearance').querySelectorAll('.mini-tab')) {
    tab.classList.toggle('active', tab.dataset.appearance === mode);
  }
  const d = state.data || {};
  setText($('#setVersion'), d.version ? 'v' + d.version : '—');
  setText($('#setPort'), d.consolePort ? ':' + d.consolePort : '—');
  setText($('#setCwd'), d.consoleCwd || '—');
}

export function openSettingsCenter() {
  syncSettings();
  openLayer(settingsMask, $('#settingsMaskClose'));
}
export function closeSettingsCenter() { closeLayer(settingsMask); }

/* ============================================================
   批量停止服务：确认后逐个走安全停止，绝不按端口结束进程
   ============================================================ */
function batchStopApps() {
  const running = ((state.data && state.data.apps) || []).filter(a => a.running);
  if (!running.length) {
    toast(t('widgets.noRunningApps'));
    return;
  }
  const names = running.map(a => a.name || t('common.unnamed'))
    .join(t('common.listSeparator'));
  openConfirm({
    title: t('widgets.batchStopTitle'),
    bodyHtml: t('widgets.batchStopConfirm', { count: running.length }) +
      '<div class="confirm-detail">' +
      t('widgets.batchStopDetail', { names: escapeHtml(names) }) + '</div>',
    okText: t('widgets.stopAll'),
    tone: 'danger',
    onOk: async () => {
      let stopped = 0;
      for (const app of running) {
        const result = await requestManagedAppStop(app);
        if (result && result.ok !== false) stopped += 1;
      }
      toast(t('widgets.stoppedCount', { count: stopped }));
      if (window.__poll) window.__poll();
    },
  });
}
