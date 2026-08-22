'use strict';
/* ============================================================
   launchpad.js — 启动台：应用卡片 / 拖拽排序 / 端口诊断 / 启动诊断
   ============================================================ */
import { $, el, setText, setChildren, setKpi, setKpiUnit, icon, iconBtn, escapeHtml,
  post, del, act, toast, openLayer, closeLayer, reconcile,
  state, findApp, fmtUptime, fmtDuration, taskExitStatus,
  localServiceUrl, executionLabel, processIdentity } from './core.js';
import { openConfirm, openAppModal, openLogs, getIconVer,
  requestManagedAppStop, requestProcessKill } from './overlays.js';
import { configuredPort, actualPorts, hasPortMismatch,
  preferredOpenPort, displayedPorts, portIsOpenable } from './ports.js';
import { t, translateKnownText, getLanguage } from './i18n.js';

const svcGrid = $('#svcGrid'), taskGrid = $('#taskGrid');
const reorderStatus = $('#reorderStatus');
/* ---------------- 图标取色光晕 ---------------- */
function hueFromString(s) {
  let h = 0;
  for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h % 360;
}
function fallbackGlow(id) { return 'hsl(' + hueFromString(id) + ' 75% 60%)'; }
/* 8x8 缩样后按透明度加权取平均色；跨域/解码失败静默回退 */
function glowFromImage(img, cb) {
  const compute = () => {
    try {
      const cv = document.createElement('canvas');
      cv.width = cv.height = 8;
      const cx = cv.getContext('2d', { willReadFrequently: true });
      cx.drawImage(img, 0, 0, 8, 8);
      const d = cx.getImageData(0, 0, 8, 8).data;
      let r = 0, g = 0, b = 0, w = 0;
      for (let i = 0; i < d.length; i += 4) {
        const a = d[i + 3] / 255;
        if (a > 0.2) { r += d[i] * a; g += d[i + 1] * a; b += d[i + 2] * a; w += a; }
      }
      if (!w) return cb(null);
      cb('rgb(' + Math.round(r / w) + ' ' + Math.round(g / w) + ' ' + Math.round(b / w) + ')');
    } catch (e) { cb(null); }
  };
  if (img.complete && img.naturalWidth) compute();
  else img.addEventListener('load', compute, { once: true });
}
function updateCardGlow(card, app) {
  const key = app.icon || app.favicon || ('id:' + app.id);
  if (card._glowKey === key) return;
  card._glowKey = key;
  if (app.icon || app.favicon) {
    glowFromImage(card._r.iconImg, c => {
      if (card._glowKey === key) card.style.setProperty('--glow', c || fallbackGlow(app.id));
    });
  } else {
    card.style.setProperty('--glow', fallbackGlow(app.id));
  }
}

const FAVICON_RETRY_DELAYS = [5000, 15000, 60000];
function maybeFetchFavicon(card, app) {
  const port = preferredOpenPort(app);
  if (app.icon || app.glyph || !app.running || !port) {
    if (app.favicon) card._favFetch = null;
    return;
  }
  /* favicon 已就位时只在加载失败后重试（_favFailedAt 记录上次失败的地址），
     正常显示的 favicon 不再重复请求。 */
  if (app.favicon && card._favFailedAt !== app.favicon) {
    card._favFetch = null;
    return;
  }
  const signature = String(app.pid || app.lastPid || port);
  if (!card._favFetch || card._favFetch.signature !== signature) {
    card._favFetch = { signature, attempts: 0, nextAt: 0, inFlight: false };
  }
  const attempt = card._favFetch;
  if (attempt.inFlight || attempt.attempts >= FAVICON_RETRY_DELAYS.length
      || Date.now() < attempt.nextAt) return;
  attempt.inFlight = true;
  attempt.attempts += 1;
  post('/api/apps/' + app.id + '/favicon', {})
    .then(result => {
      if (result && result.ok) window.__poll();
      else attempt.nextAt = Date.now() + FAVICON_RETRY_DELAYS[attempt.attempts - 1];
    })
    .catch(() => {
      attempt.nextAt = Date.now() + FAVICON_RETRY_DELAYS[attempt.attempts - 1];
    })
    .finally(() => { attempt.inFlight = false; });
}

function createAppCard() {
  const card = el('article', 'app-card');
  card.tabIndex = 0;
  card.setAttribute('aria-describedby', 'reorderInstructions');
  card.setAttribute('aria-roledescription', t('launchpad.cardRole'));
  card.addEventListener('pointerdown', cardPointerDown);
  card.addEventListener('keydown', cardSortKeyDown);

  const head = el('div', 'app-head');
  const iconBox = el('div', 'app-icon');
  const iconImg = new Image();
  iconImg.alt = '';
  iconImg.hidden = true;
  iconImg.addEventListener('error', () => {
    iconImg._failedSrc = iconImg.getAttribute('src') || '';
    iconImg.hidden = true;
    iconGlyph.hidden = true;
    iconTxt.hidden = false;
    const app = findApp(card.dataset.key);
    setText(iconTxt, app && app.name ? [...app.name][0].toUpperCase() : '?');
    /* favicon 已保存但图片加载失败（404/损坏）：按重试延迟再次抓取，
       否则 app.favicon 一旦被设置就永远停在字母占位。 */
    if (app && app.favicon && iconImg._failedSrc === app.favicon) {
      card._favFailedAt = app.favicon;
      const attempt = card._favFetch;
      const signature = String(app.pid || app.lastPid || preferredOpenPort(app));
      if (attempt && attempt.signature === signature) {
        const delayIndex = Math.max(0, Math.min(
          attempt.attempts - 1, FAVICON_RETRY_DELAYS.length - 1));
        attempt.nextAt = Date.now() + FAVICON_RETRY_DELAYS[delayIndex];
      } else {
        card._favFetch = {
          signature, attempts: 0,
          nextAt: Date.now() + FAVICON_RETRY_DELAYS[0],
          inFlight: false,
        };
      }
    }
  });
  iconImg.addEventListener('load', () => {
    iconImg._failedSrc = '';
    card._favFailedAt = '';
  });
  const iconGlyph = el('span', 'app-icon-glyph');
  iconGlyph.hidden = true;
  const iconTxt = el('span', 'app-icon-letter');
  iconBox.append(iconImg, iconGlyph, iconTxt);

  const meta = el('div', 'app-meta');
  const name = el('div', 'app-name');
  const execution = el('div', 'execution-badge');
  execution.hidden = true;
  const status = el('div', 'app-status');
  const dot = el('span', 'status-dot');
  const stText = el('span', 'st-text');
  const stPort = el('button', 'st-port');
  stPort.type = 'button';
  const stUp = el('span', 'st-up');
  status.append(dot, stText, stPort, stUp);
  const taskHistory = el('div', 'task-history');
  taskHistory.hidden = true;
  meta.append(name, execution, status, taskHistory);
  head.append(iconBox, meta);

  const cmd = el('div', 'app-cmd');

  const actions = el('div', 'app-actions');
  const primary = el('button', 'btn app-primary');
  primary.type = 'button';
  const sub = el('div', 'app-sub-actions');
  const bCopy = iconBtn('copy', t('launchpad.copyLink'));
  const bLogs = iconBtn('file-text', t('common.logs'));
  const bDiag = iconBtn('activity', t('launchpad.startDiagnosis'));
  bDiag.hidden = true;
  const bRestart = iconBtn('refresh-cw', t('launchpad.restartApp'));
  bRestart.hidden = true;
  const bEdit = iconBtn('pencil', t('common.edit'));
  const bDel = iconBtn('trash-2', t('common.delete'), 'danger');
  sub.append(bCopy, bLogs, bDiag, bRestart, bEdit, bDel);
  actions.append(primary, sub);

  card.append(head, cmd, actions);
  card._r = { iconBox, iconImg, iconGlyph, iconTxt, name, execution, status, dot,
    stText, stPort, stUp, taskHistory, cmd, primary, copy: bCopy, logs: bLogs,
    diag: bDiag, restart: bRestart, edit: bEdit, del: bDel };

  const id = () => card.dataset.key;
  primary.addEventListener('click', () => toggleApp(id(), primary));
  bCopy.addEventListener('click', async () => {
    const a = findApp(id());
    const p = preferredOpenPort(a);
    if (!p) return;
    const url = localServiceUrl(a, p);
    try {
      await navigator.clipboard.writeText(url);
      toast(t('launchpad.copied', { url }));
    } catch (e) {
      toast(t('errors.copyFailed', { message: e.message }));
    }
  });
  stPort.addEventListener('click', () => {
    const a = findApp(id());
    const p = preferredOpenPort(a);
    if (a && (a.portConflict || a.portOccupied)) {
      openPortDiagnostic(a);
      return;
    }
    /* listening 是新后端字段；旧进程热加载前会缺失，缺失时保持兼容。 */
    if (portIsOpenable(a) && p) {
      window.open(localServiceUrl(a, p), '_blank', 'noopener,noreferrer');
    }
  });
  bLogs.addEventListener('click', () => { const a = findApp(id()); if (a) openLogs(a); });
  bDiag.addEventListener('click', () => { const a = findApp(id()); if (a) openAppDiagnosis(a); });
  bRestart.addEventListener('click', () => {
    const a = findApp(id());
    if (a) confirmRestartApp(a);
  });
  bEdit.addEventListener('click', () => { const a = findApp(id()); if (a) openAppModal(a); });
  bDel.addEventListener('click', () => { const a = findApp(id()); if (a) confirmDeleteApp(a); });
  return card;
}

/* 主按钮：服务 = 启动/停止；批处理 = 运行/中止。 */
function setPrimary(btn, running, kind) {
  const labelKey = running ? (kind === 'task' ? 'common.abort' : 'common.stop')
    : (kind === 'task' ? 'common.run' : 'common.start');
  const label = t(labelKey);
  const sig = running + '|' + kind + '|' + label;
  if (btn._sig === sig) return;
  btn._sig = sig;
  setChildren(btn, icon(running ? 'square' : 'play', 13));
  btn.appendChild(document.createTextNode(label));
  btn.classList.toggle('btn-stop', running);
  btn.classList.toggle('btn-accent', !running);
}

function lastExitAgo(lastExit) {
  const endedAt = Number(lastExit && lastExit.at);
  if (!Number.isFinite(endedAt) || endedAt <= 0) return '';
  const ago = fmtUptime(Date.now() / 1000 - endedAt);
  return ago === t('time.justNow') ? ago : t('time.ago', { time: ago });
}

function updateAppCard(card, app) {
  const r = card._r;
  card.setAttribute('aria-roledescription', t('launchpad.cardRole'));
  /* 图标优先级：上传图片 > glyph（Lucide）> 站点 favicon（自动抓取）> 名称首字 */
  const v = getIconVer(app.id);
  if (app.icon) {
    r.iconImg.classList.remove('fav');
    const src = app.icon + (v ? '?v=' + v : '');
    if (r.iconImg.getAttribute('src') !== src) {
      r.iconImg._failedSrc = '';
      r.iconImg.src = src;
    }
    const failed = r.iconImg._failedSrc === src;
    r.iconImg.hidden = failed;
    r.iconGlyph.hidden = true;
    r.iconTxt.hidden = !failed;
    if (failed) setText(r.iconTxt, app.name ? [...app.name][0].toUpperCase() : '?');
  } else if (app.glyph && window.LUCIDE && window.LUCIDE[app.glyph]) {
    if (r._glyph !== app.glyph) {
      r._glyph = app.glyph;
      setChildren(r.iconGlyph, icon(app.glyph, 22));
    }
    r.iconGlyph.hidden = false;
    r.iconImg.hidden = true;
    r.iconTxt.hidden = true;
  } else if (app.favicon) {
    r.iconImg.classList.add('fav');
    if (r.iconImg.getAttribute('src') !== app.favicon) {
      r.iconImg._failedSrc = '';
      r.iconImg.src = app.favicon;
    }
    const failed = r.iconImg._failedSrc === app.favicon;
    r.iconImg.hidden = failed;
    r.iconGlyph.hidden = true;
    r.iconTxt.hidden = !failed;
    if (failed) setText(r.iconTxt, app.name ? [...app.name][0].toUpperCase() : '?');
  } else {
    r._glyph = null;
    r.iconImg.hidden = true;
    r.iconGlyph.hidden = true;
    r.iconTxt.hidden = false;
    setText(r.iconTxt, app.name ? [...app.name][0].toUpperCase() : '?');
  }
  setText(r.name, app.name || '');
  r.name.title = app.name || '';
  const executionText = executionLabel(app);
  setText(r.execution, executionText);
  r.execution.hidden = !executionText;
  r.execution.title = executionText;
  setText(r.cmd, app.command || '');
  r.cmd.title = app.command || '';
  /* 状态副行：运行态、端口冲突，以及服务/任务上次退出结果。 */
  const kind = app.kind || 'service';
  const isTask = kind === 'task';
  const taskStatus = isTask && app.lastExit ? taskExitStatus(app.lastExit) : '';
  const taskFinished = isTask && !app.running && !!app.lastExit;
  const taskFailed = taskFinished && taskStatus === 'failed';
  const taskSucceeded = taskFinished && taskStatus === 'succeeded';
  const healthIssues = app.health && Array.isArray(app.health.issues)
    ? app.health.issues : [];
  const healthIssue = app.health && app.health.blocking && healthIssues.length
    ? healthIssues[0] : null;
  const healthTitle = healthIssue
    ? translateKnownText(healthIssue.title || '') : '';
  const healthDetail = healthIssue
    ? translateKnownText(healthIssue.detail || '') : '';
  const portMismatch = hasPortMismatch(app);
  r.dot.classList.toggle('running', !!app.running);
  r.dot.classList.toggle('success', taskSucceeded);
  r.dot.classList.toggle('danger', taskFailed);
  let stTxt = t(app.running ? 'launchpad.status.running'
    : app.port ? 'launchpad.status.stopped' : 'launchpad.status.notRun');
  let stFail = false;
  let taskHistoryText = '';
  if (app.portConflict) {
    stTxt = t('launchpad.status.configConflict');
    stFail = true;
  } else if (app.portOccupied) {
    stTxt = t('launchpad.status.portOccupied');
    stFail = true;
  } else if (portMismatch) {
    stTxt = t('launchpad.status.portMismatch');
    stFail = true;
  } else if (app.running && app.port && app.listening === false) {
    stTxt = t('launchpad.status.waitingPort');
  } else if (!app.running && healthIssue) {
    stTxt = healthTitle || t('launchpad.status.configUnavailable');
    stFail = true;
  } else if (taskFinished && (taskStatus === 'canceled' || taskStatus === 'stopped')) {
    stTxt = t(taskStatus === 'canceled' ? 'common.canceled' : 'common.aborted');
    taskHistoryText = lastExitAgo(app.lastExit);
  } else if (!app.running && app.lastExit) {
    const ok = isTask ? taskStatus === 'succeeded' : app.lastExit.code === 0;
    stFail = !ok;
    const agoText = lastExitAgo(app.lastExit);
    const what = app.port
      ? (ok ? t('launchpad.status.serviceExited')
        : (app.lastExit.code < 0 ? t('launchpad.status.serviceTerminated')
          : t('launchpad.status.startFailed', { code: app.lastExit.code })))
      : (ok ? t('launchpad.status.runSucceeded')
        : (app.lastExit.code < 0 ? t('launchpad.status.runTerminated')
          : t('launchpad.status.runFailed', { code: app.lastExit.code })));
    if (isTask) {
      stTxt = what;
      const duration = fmtDuration(app.lastExit.durationSec);
      taskHistoryText = t('launchpad.status.history', {
        ago: agoText,
        duration: duration
          ? (agoText ? ' · ' : '') + t('time.used', { duration }) : '',
      });
    } else {
      stTxt = agoText ? what + ' · ' + agoText : what;
    }
  }
  setText(r.stText, stTxt);
  r.stText.classList.toggle('fail', stFail);
  setText(r.taskHistory, taskHistoryText);
  r.taskHistory.hidden = !taskHistoryText;
  r.taskHistory.title = taskHistoryText;
  r.status.title = taskHistoryText ? stTxt + ' · ' + taskHistoryText : stTxt;
  card.setAttribute('aria-label', t('launchpad.cardAria', {
    name: app.name || t('common.unnamed'),
    status: stTxt,
  }));
  /* 运行中展示并打开实际监听端口；停止时才展示配置端口。 */
  const effPorts = displayedPorts(app);
  const effPort = preferredOpenPort(app);
  r.copy.hidden = !effPort;
  if (effPort) {
    r.stPort.hidden = false;
    setText(r.stPort, portMismatch
      ? ':' + effPort + (effPorts.length > 1 ? ' +' + (effPorts.length - 1) : '') +
        ' ≠ :' + configuredPort(app)
      : ':' + effPort + (effPorts.length > 1 ? ' +' + (effPorts.length - 1) : ''));
    const openable = portIsOpenable(app);
    const diagnostic = !!app.portConflict || !!app.portOccupied;
    r.stPort.classList.toggle('clickable', openable && !diagnostic);
    r.stPort.classList.toggle('diagnostic', diagnostic);
    if (app.portConflict) {
      r.stPort.title = t('launchpad.portConflictTitle', {
        apps: (app.portConflictApps || []).join(t('common.listSeparator')),
      });
    } else if (app.portOccupied) {
      r.stPort.title = t('launchpad.portOccupiedTitle', {
        pid: app.portOccupiedPid || '?',
      });
    } else if (portMismatch) {
      r.stPort.title = t('launchpad.portMismatchTitle', {
        configured: configuredPort(app),
        actual: effPorts.map(port => ':' + port).join(t('common.listSeparator')),
      });
    } else if (openable) {
      r.stPort.title = t('launchpad.portOpenTitle', {
        url: localServiceUrl(app, effPort),
        all: effPorts.length > 1
          ? t('launchpad.portAll', { ports: effPorts.join(', ') }) : '',
      });
    } else {
      r.stPort.title = t('launchpad.portTitle', { port: effPort });
    }
    const portAppName = app.name || t('common.application');
    r.stPort.setAttribute('aria-label', diagnostic
      ? t('launchpad.portDiagnoseAria', { name: portAppName, port: effPort })
      : openable
        ? t('launchpad.portOpenAria', {
          name: portAppName,
          port: effPort,
          kind: t(portMismatch ? 'common.actual' : 'common.port'),
        })
        : t('launchpad.portAria', { name: portAppName, port: effPort }));
  } else {
    r.stPort.hidden = true;
    r.stPort.removeAttribute('aria-label');
  }
  if (app.running) {
    r.stUp.hidden = false;
    setText(r.stUp, isTask ? fmtDuration(app.uptimeSec) : fmtUptime(app.uptimeSec));
  } else {
    r.stUp.hidden = true;
    setText(r.stUp, '');
  }
  setPrimary(r.primary, !!app.running, kind);
  const appName = app.name || t(isTask ? 'common.task' : 'common.application');
  const primaryActionKey = app.running
    ? (isTask ? 'palette.abortNamed' : 'palette.stopNamed')
    : (isTask ? 'palette.runNamed' : 'palette.startNamed');
  r.primary.setAttribute('aria-label', t(primaryActionKey, { name: appName }));
  r.copy.setAttribute('aria-label', t('launchpad.copyAria', { name: appName }));
  r.logs.setAttribute('aria-label', t(taskFailed
    ? 'launchpad.failedLogsAria' : 'launchpad.logsAria',
  { name: appName }));
  r.diag.setAttribute('aria-label', t(isTask
    ? 'launchpad.runDiagnosis' : 'launchpad.configDiagnosis',
  { name: appName }));
  r.restart.setAttribute('aria-label', t('launchpad.restartAria', { name: appName }));
  r.edit.setAttribute('aria-label', t('launchpad.editAria', { name: appName }));
  r.del.setAttribute('aria-label', t('launchpad.deleteAria', { name: appName }));
  card.setAttribute('aria-label', t('launchpad.cardAria', { name: appName, status: stTxt }));
  r.restart.hidden = !app.running || kind !== 'service';
  const blocked = !app.running &&
    (!!app.portConflict || !!app.portOccupied || !!healthIssue);
  r.primary.disabled = blocked;
  r.primary.title = app.portConflict
    ? t('launchpad.portConflictHint')
    : app.portOccupied ? t('launchpad.portOccupiedHint')
      : healthIssue ? healthDetail || healthTitle : '';
  const launchFailed = !app.running && !!app.lastExit
    && (isTask ? taskStatus === 'failed' : app.lastExit.code !== 0);
  card.classList.toggle('running', !!app.running);
  card.classList.toggle('has-error', !!app.portConflict || !!app.portOccupied
    || portMismatch || launchFailed || !!healthIssue);
  r.diag.hidden = !launchFailed && !healthIssue;
  updateCardGlow(card, app);
  r.logs.classList.toggle('attention', taskFailed);
  r.copy.title = t('launchpad.copyLink');
  r.logs.title = t(taskFailed ? 'launchpad.failedLogs' : 'launchpad.logs');
  r.diag.title = t('launchpad.startDiagnosis');
  r.restart.title = t('launchpad.restartApp');
  r.edit.title = t('common.edit');
  r.del.title = t('common.delete');
  maybeFetchFavicon(card, app);
}

async function toggleApp(id, button) {
  const app = findApp(id);
  if (!app) return;
  const isTask = (app.kind || 'service') === 'task';
  if (button && button.dataset.busy === 'true') return;
  if (!app.running && app.portConflict) {
    toast(t('launchpad.portConflictHint'));
    return;
  }
  if (!app.running && app.portOccupied) {
    toast(t('launchpad.portOccupiedTitle', { pid: app.portOccupiedPid || '?' }));
    return;
  }
  const starting = !app.running;
  if (button) {
    button.dataset.busy = 'true';
    button.disabled = true;
  }
  const targetName = app.name || t(isTask ? 'common.task' : 'common.application');
  toast(t(starting
    ? (isTask ? 'launchpad.action.runningTask' : 'launchpad.action.startingService')
    : (isTask ? 'launchpad.action.abortingTask' : 'launchpad.action.stoppingService'),
  { name: targetName }));
  try {
    const result = starting
      ? await act(post('/api/apps/' + id + '/start', {}))
      : await requestManagedAppStop(app);
    if (result && result.ok !== false) {
      if (starting) {
        toast(isTask
          ? t('launchpad.action.taskStarted', { name: targetName })
          : t('launchpad.action.waitingService', {
            target: app.port ? ' :' + app.port : t('common.service'),
          }));
        await window.__poll();
        setTimeout(window.__poll, 700);
        setTimeout(window.__poll, 1800);
      } else {
        await window.__poll();
        toast(t(isTask
          ? 'launchpad.action.taskAborted' : 'launchpad.action.serviceStopped',
        { name: targetName }));
      }
    } else {
      await window.__poll();
    }
  } finally {
    if (button) {
      delete button.dataset.busy;
      const latest = findApp(id);
      button.disabled = !!(latest && !latest.running &&
        (latest.portConflict || latest.portOccupied ||
          (latest.health && latest.health.blocking)));
    }
  }
}
export { toggleApp };

function confirmRestartApp(app) {
  const appName = app.name || t('common.application');
  openConfirm({
    title: t('launchpad.restartApp'),
    bodyHtml: t('launchpad.restartConfirm', {
      name: '<b>' + escapeHtml(appName) + '</b>',
    }) + '<div class="confirm-detail">' + t('launchpad.restartDetail') + '</div>',
    okText: t('common.restart'),
    onOk: async () => {
      const r = await act(post('/api/apps/' + app.id + '/restart'));
      if (r && r.ok !== false) toast(t('launchpad.restarted', { name: appName }));
      window.__poll();
    },
  });
}

function confirmDeleteApp(app) {
  const appName = app.name || t('common.application');
  openConfirm({
    title: t('launchpad.deleteTitle'),
    bodyHtml: t('launchpad.deleteConfirm', {
      name: '<b>' + escapeHtml(appName) + '</b>',
    }) + '<div class="confirm-detail">' + t('launchpad.deleteDetail') + '</div>',
    okText: t('common.delete'),
    onOk: async () => {
      await act(del('/api/apps/' + app.id));
      window.__poll();
    },
  });
}

/* ---------------- 端口诊断模态 ---------------- */
const portDiagMask = $('#portDiagMask'), portDiagTitle = $('#portDiagTitle');
const diagDot = $('#diagDot'), diagSummary = $('#diagSummary'), diagPort = $('#diagPort');
const diagPidRow = $('#diagPidRow'), diagPid = $('#diagPid');
const diagNameRow = $('#diagNameRow'), diagName = $('#diagName');
const diagAppRow = $('#diagAppRow'), diagApp = $('#diagApp');
const diagUptimeRow = $('#diagUptimeRow'), diagUptime = $('#diagUptime');
const diagCwdRow = $('#diagCwdRow'), diagCwd = $('#diagCwd');
const diagCmdRow = $('#diagCmdRow'), diagCmd = $('#diagCmd');
const diagNote = $('#diagNote'), diagCopy = $('#diagCopy');
const diagOpen = $('#diagOpen'), diagEdit = $('#diagEdit');
const diagAttach = $('#diagAttach');
const diagKill = $('#diagKill'), diagClose = $('#diagClose');

let diagCurrentApp = null;

function setDiagRow(row, node, value) {
  const present = value !== null && value !== undefined && value !== '';
  row.hidden = !present;
  if (present) setText(node, String(value));
}

function renderPortDiagnostic(app) {
  const owner = app.portOwner || null;
  const conflict = !!app.portConflict;
  const occupied = !!app.portOccupied;
  portDiagTitle.textContent = t('portDiag.titlePort', { port: app.port || '--' });
  setText(diagPort, app.port ? ':' + app.port : '--');
  diagDot.classList.toggle('danger', conflict || occupied);
  setText(diagSummary, t(conflict ? 'portDiag.summary.conflict'
    : occupied ? 'portDiag.summary.occupied' : 'portDiag.summary.ok'));

  setDiagRow(diagPidRow, diagPid, owner && owner.pid);
  setDiagRow(diagNameRow, diagName, owner && owner.name);
  setDiagRow(diagAppRow, diagApp, owner && owner.appName);
  setDiagRow(diagUptimeRow, diagUptime,
    owner && owner.uptimeSec != null ? fmtUptime(owner.uptimeSec) : null);
  setDiagRow(diagCwdRow, diagCwd, owner && owner.cwd);
  setDiagRow(diagCmdRow, diagCmd, owner && owner.cmd);

  if (conflict) {
    diagNote.textContent = t('portDiag.note.conflict', {
      apps: (app.portConflictApps || []).join(t('common.listSeparator')),
    });
  } else if (owner && owner.pid === (state.data && state.data.consolePid)) {
    diagNote.textContent = t('portDiag.note.console');
  } else if (owner && owner.currentUser) {
    const ownerLabel = owner.project || owner.appName || owner.name || ('PID ' + owner.pid);
    diagNote.textContent = t(owner.appId
      ? 'portDiag.note.managedOwner' : 'portDiag.note.externalOwner',
    { owner: ownerLabel });
  } else if (owner) {
    diagNote.textContent = t('portDiag.note.otherUser');
  } else {
    diagNote.textContent = t('portDiag.note.unknown');
  }
  diagOpen.hidden = !(occupied && owner && app.port);
  diagAttach.hidden = !(occupied && owner && owner.currentUser && !owner.appId
    && owner.pid !== (state.data && state.data.consolePid));
  diagEdit.hidden = !(conflict || occupied);
  diagKill.hidden = !(occupied && owner && owner.currentUser
    && owner.pid !== (state.data && state.data.consolePid));
  diagKill.textContent = t(owner && owner.appId
    ? 'portDiag.stopOwnerApp' : 'portDiag.killOwner');
}

function openPortDiagnostic(app) {
  diagCurrentApp = app;
  renderPortDiagnostic(app);
  openLayer(portDiagMask, diagClose);
}

function closePortDiagnostic() {
  closeLayer(portDiagMask);
  diagCurrentApp = null;
}
export { closePortDiagnostic };

diagClose.addEventListener('click', closePortDiagnostic);
portDiagMask.addEventListener('mousedown', e => {
  if (e.target === portDiagMask) closePortDiagnostic();
});
diagOpen.addEventListener('click', () => {
  const app = diagCurrentApp;
  if (!app || !app.port) return;
  window.open(localServiceUrl(app.portOwner, app.port), '_blank', 'noopener,noreferrer');
});
diagEdit.addEventListener('click', () => {
  const app = diagCurrentApp;
  if (!app) return;
  closePortDiagnostic();
  openAppModal(app);
});
diagAttach.addEventListener('click', () => {
  const app = diagCurrentApp;
  const owner = app && app.portOwner;
  if (!app || !owner) return;
  closePortDiagnostic();
  openConfirm({
    title: t('portDiag.attachConfirmTitle'),
    bodyHtml: t('portDiag.attachConfirm', {
      pid: escapeHtml(owner.pid),
      process: escapeHtml(owner.name || ''),
      app: escapeHtml(app.name || t('common.application')),
    }) + '<div class="confirm-detail">' + t('portDiag.attachDetail') + '</div>',
    okText: t('portDiag.attachAction'),
    onOk: async () => {
      const identity = processIdentity(owner);
      if (!identity.instanceKey && identity.pid == null) {
        toast(t('errors.safeIdentityMissing'));
        return;
      }
      const r = await act(post('/api/apps/' + app.id + '/attach', identity));
      if (r && r.ok) {
        toast(t(r.cwdUpdated ? 'portDiag.attachedCwd' : 'portDiag.attached'));
      }
      window.__poll();
    },
  });
});
diagCopy.addEventListener('click', async () => {
  const app = diagCurrentApp;
  if (!app) return;
  const owner = app.portOwner || {};
  const lines = [
    t('portDiag.infoPort', { port: app.port || '--' }),
    owner.pid ? 'PID: ' + owner.pid : '',
    owner.name ? t('portDiag.infoProgram', { program: owner.name }) : '',
    owner.cwd ? t('portDiag.infoDirectory', { directory: owner.cwd }) : '',
    owner.cmd ? t('portDiag.infoCommand', { command: owner.cmd }) : '',
    app.portConflict ? t('portDiag.infoConflict', {
      apps: (app.portConflictApps || []).join(t('common.listSeparator')),
    }) : '',
  ].filter(Boolean).join('\n');
  try {
    await navigator.clipboard.writeText(lines);
    toast(t('portDiag.copied'));
  } catch (e) {
    toast(t('errors.copyFailed', { message: e.message }));
  }
});
diagKill.addEventListener('click', () => {
  const app = diagCurrentApp;
  const owner = app && app.portOwner;
  if (!owner) return;
  closePortDiagnostic();
  openConfirm({
    title: t(owner.appId ? 'portDiag.stopOwnerApp' : 'portDiag.killOwner'),
    bodyHtml: t('portDiag.releaseConfirm', {
      port: '<b>' + escapeHtml(app.port) + '</b>',
    }) +
      '<div class="confirm-detail mono">PID ' + escapeHtml(owner.pid) +
      ' · ' + escapeHtml(owner.name || '') + '</div>',
    okText: t(owner.appId ? 'portDiag.stopApp' : 'portDiag.killProcess'),
    onOk: async () => {
      if (owner.appId) {
        const linked = findApp(owner.appId) || {
          id: owner.appId,
          name: owner.appName || owner.name || t('portDiag.ownerFallback'),
          kind: 'service',
        };
        await requestManagedAppStop(linked);
      } else await requestProcessKill(owner);
      window.__poll();
    },
  });
});

/* ---------------- 启动诊断模态 ---------------- */
const appDiagMask = $('#appDiagMask'), appDiagList = $('#appDiagList');
const appDiagTitle = $('#appDiagTitle');
const appDiagSummary = $('#appDiagSummary'), appDiagLogs = $('#appDiagLogs');
const appDiagClose = $('#appDiagClose');
let appDiagApp = null;
let appDiagRequestSeq = 0;
let appDiagResponse = null;

function renderAppDiagnosis(app, response, loading = false) {
  const isTask = (app.kind || 'service') === 'task';
  setText(appDiagTitle, t(isTask ? 'diagnose.runTitle' : 'diagnose.startTitle', {
    name: app.name || t('common.application'),
  }));
  appDiagList.replaceChildren();
  appDiagList.setAttribute('aria-busy', String(loading));
  if (loading) {
    setText(appDiagSummary, t('diagnose.analyzing'));
    return;
  }
  if (!response || response.ok === false) {
    setText(appDiagSummary, response && response.error
      ? translateKnownText(response.error) : t('diagnose.failed'));
    return;
  }
  for (const issue of response.issues || []) {
    const box = el('div', 'appdiag-issue');
    const h = el('h4');
    h.textContent = translateKnownText(issue.title || '');
    const d = el('p', 'appdiag-detail');
    d.textContent = translateKnownText(issue.detail || '');
    const f = el('p', 'appdiag-fix');
    f.textContent = t('diagnose.fixPrefix', {
      fix: translateKnownText(issue.fix || ''),
    });
    box.append(h, d, f);
    if (issue.action) {
      const repair = el('button', 'btn appdiag-repair');
      repair.type = 'button';
      repair.textContent = t(issue.action === 'pick-script' ? 'diagnose.pickScript'
        : issue.action === 'pick-cwd' ? 'diagnose.pickWorkspace' : 'diagnose.editCommand');
      repair.addEventListener('click', () => {
        const target = appDiagApp;
        closeAppDiagnosis();
        if (target) openAppModal(target, null, issue.action);
      });
      box.appendChild(repair);
    }
    appDiagList.appendChild(box);
  }
  setText(appDiagSummary, (response.issues || []).length
    ? t('diagnose.summary.found', { count: response.issues.length })
    : translateKnownText(response.summary || ''));
}

async function openAppDiagnosis(app) {
  const requestSeq = ++appDiagRequestSeq;
  appDiagApp = app;
  appDiagResponse = null;
  renderAppDiagnosis(app, null, true);
  openLayer(appDiagMask, appDiagClose);
  let r = null;
  try {
    r = await post('/api/apps/' + app.id + '/diagnose', {});
  } catch (e) {
    if (requestSeq === appDiagRequestSeq && appDiagApp && appDiagApp.id === app.id) {
      toast(t('diagnose.requestFailed', { message: e.message }));
    }
  }
  if (requestSeq !== appDiagRequestSeq || !appDiagApp || appDiagApp.id !== app.id) return;
  appDiagResponse = r || { ok: false };
  renderAppDiagnosis(app, appDiagResponse);
}
function closeAppDiagnosis() {
  appDiagRequestSeq += 1;
  appDiagList.setAttribute('aria-busy', 'false');
  closeLayer(appDiagMask);
  appDiagApp = null;
  appDiagResponse = null;
}
export { closeAppDiagnosis };

appDiagClose.addEventListener('click', closeAppDiagnosis);
appDiagMask.addEventListener('mousedown', e => {
  if (e.target === appDiagMask) closeAppDiagnosis();
});
appDiagLogs.addEventListener('click', () => {
  const a = appDiagApp;
  closeAppDiagnosis();
  if (a) openLogs(a);
});

/* ---------------- 卡片拖拽排序（pointer 实现：滑块式跟手 + 虚线占位） ---------------- */
let drag = null;  // { card, ph, grid, dx, dy, originIndex }
let keyboardSort = null;  // { card, grid, originalIds }
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function gridAppCards(grid) {
  return [...grid.querySelectorAll('.app-card[data-key]')];
}

function persistGridOrder(ids) {
  return post('/api/apps/reorder', { ids })
    .then(() => window.__poll())
    .catch(() => toast(t('reorder.saveFailed')));
}

function announceReorder(message) {
  if (!reorderStatus) return;
  reorderStatus.textContent = '';
  requestAnimationFrame(() => { reorderStatus.textContent = message; });
}

/* FLIP 让位动画：重排前记录视觉位置，重排后从旧位置滑到新位置。 */
function flip(grid, mutate) {
  if (reduceMotion) { mutate(); return; }
  const cards = [...grid.querySelectorAll('.app-card, .drop-placeholder')];
  const first = new Map(cards.map(c => [c, c.getBoundingClientRect()]));
  for (const c of cards) {
    clearTimeout(c._flipT);
    c.style.transition = 'none';
    c.style.transform = 'none';
  }
  mutate();
  const moved = [];
  for (const c of cards) {
    if (!c.isConnected) continue;
    const f = first.get(c), l = c.getBoundingClientRect();
    const dx = f.left - l.left, dy = f.top - l.top;
    if (dx || dy) {
      c.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
      moved.push(c);
    } else {
      c.style.transition = '';
      c.style.transform = '';
    }
  }
  if (!moved.length) return;
  requestAnimationFrame(() => {
    for (const c of moved) {
      c.style.transition = 'transform 0.2s ease-out';
      c.style.transform = '';
      c._flipT = setTimeout(() => { c.style.transition = ''; c.style.transform = ''; }, 220);
    }
  });
}

function cardPointerDown(e) {
  if (e.button !== 0 || drag || keyboardSort) return;
  if (e.target.closest('button')) return;   // 按钮上不触发拖拽
  const card = e.currentTarget;
  const sx = e.clientX, sy = e.clientY;
  const clearListeners = () => {
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onCancel);
  };
  const onMove = ev => {
    if (!drag) {
      if (Math.abs(ev.clientX - sx) + Math.abs(ev.clientY - sy) < 6) return;  // 点击阈值
      beginDrag(card, ev);
    }
    moveDrag(ev);
  };
  const onUp = () => {
    clearListeners();
    if (drag) endDrag();
  };
  const onCancel = () => {
    clearListeners();
    if (drag) cancelPointerDrag();
  };
  window.addEventListener('pointermove', onMove);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onCancel);
}

function beginDrag(card, e) {
  const grid = card.parentNode;
  const rect = card.getBoundingClientRect();
  const originIndex = gridAppCards(grid).indexOf(card);
  const ph = el('div', 'drop-placeholder');
  ph.style.height = rect.height + 'px';
  grid.insertBefore(ph, card);
  document.body.appendChild(card);   // 卡片脱离 grid，fixed 跟随指针
  const s = card.style;
  s.width = rect.width + 'px';
  s.height = rect.height + 'px';
  s.position = 'fixed';
  s.left = '0';
  s.top = '0';
  s.margin = '0';
  s.zIndex = '200';
  s.pointerEvents = 'none';          // 穿透，便于 elementFromPoint 找目标
  card.classList.add('lifted');
  document.body.classList.add('dragging-on');
  drag = {
    card, ph, grid, originIndex,
    dx: e.clientX - rect.left,
    dy: e.clientY - rect.top,
  };
  moveDrag(e);
}

function moveDrag(e) {
  const d = drag;
  d.card.style.transform =
    'translate(' + (e.clientX - d.dx) + 'px,' + (e.clientY - d.dy) + 'px)';
  const hit = document.elementFromPoint(e.clientX, e.clientY);
  const over = hit && hit.closest('.app-card');
  if (over && d.grid.contains(over) && !over.classList.contains('add-card')) {
    /* 用布局坐标（offsetLeft，不含 FLIP transform）判定插入侧，
       避免让位动画中的视觉位置抖动导致占位框来回振荡 */
    const baseX = over.offsetParent.getBoundingClientRect().left;
    const midX = over.offsetLeft + over.offsetWidth / 2;
    const before = (e.clientX - baseX) < midX;
    const ref = before ? over : over.nextSibling;
    if (d.ph.nextSibling !== ref) {   // 位置没变则跳过，避免 FLIP 动画被重启
      flip(d.grid, () => d.grid.insertBefore(d.ph, ref));
    }
  } else if (over && d.grid.contains(over)) {
    /* 添加卡上 → 网格末尾。添加卡被 prepend 到网格首位，
       insertBefore(d.ph, over) 会把卡片插到首位，与“末尾”意图相反。 */
    if (d.ph !== d.grid.lastChild) {
      flip(d.grid, () => d.grid.appendChild(d.ph));
    }
  }
}

function resetPointerDragCard(d) {
  const s = d.card.style;
  s.position = s.left = s.top = s.width = s.height = s.margin =
    s.zIndex = s.transform = s.transition = s.pointerEvents = '';
  d.card.classList.remove('lifted');
  document.body.classList.remove('dragging-on');
}

function cancelPointerDrag() {
  const d = drag;
  drag = null;
  const remaining = gridAppCards(d.grid);
  const anchor = remaining[d.originIndex] || null;
  if (anchor) d.grid.insertBefore(d.card, anchor);
  else d.grid.appendChild(d.card);
  d.ph.remove();
  resetPointerDragCard(d);
  d.card.focus({ preventScroll: true });
  announceReorder(t('reorder.canceled'));
}

/* drop 瞬间的最终顺序：卡片脱离 grid 时占位框位置即目标位置。
   必须在 180ms 滑入动画开始前快照——动画窗口内轮询可能按服务端旧顺序
   重排 DOM，届时重读 DOM 会把被撤销的顺序 POST 回去，排序静默丢失。 */
function dragDropOrder(d) {
  const ids = gridAppCards(d.grid).map(card => card.dataset.key);
  const children = [...d.grid.children];
  const before = children.slice(0, children.indexOf(d.ph))
    .filter(child => child.matches('.app-card[data-key]')).length;
  ids.splice(before, 0, d.card.dataset.key);
  return ids;
}

function endDrag() {
  const d = drag;
  drag = null;
  const orderSnapshot = dragDropOrder(d);
  const finish = () => {
    d.grid.insertBefore(d.card, d.ph);
    d.ph.remove();
    resetPointerDragCard(d);
    persistGridOrder(orderSnapshot);
  };
  if (reduceMotion) { finish(); return; }
  const t = d.ph.getBoundingClientRect();   // 滑入占位框
  d.card.style.transition = 'transform 0.18s ease-out';
  d.card.style.transform = 'translate(' + t.left + 'px,' + t.top + 'px)';
  setTimeout(finish, 180);
}

function cardSortKeyDown(e) {
  if (e.target !== e.currentTarget) return;
  const card = e.currentTarget;
  const isSpace = e.key === ' ' || e.key === 'Spacebar';
  if (!keyboardSort) {
    if (!isSpace) return;
    e.preventDefault();
    const grid = card.parentNode;
    const cards = gridAppCards(grid);
    keyboardSort = {
      card,
      grid,
      originalIds: cards.map(item => item.dataset.key),
    };
    card.classList.add('keyboard-sorting');
    const position = cards.indexOf(card) + 1;
    announceReorder(t('reorder.grabbed', {
      name: findApp(card.dataset.key)?.name || t('common.application'),
      position,
      count: cards.length,
    }));
    return;
  }
  if (keyboardSort.card !== card) return;
  if (isSpace || e.key === 'Enter') {
    e.preventDefault();
    finishKeyboardSort(true);
    return;
  }
  if (e.key === 'Escape') {
    e.preventDefault();
    finishKeyboardSort(false);
    return;
  }
  const direction = (e.key === 'ArrowLeft' || e.key === 'ArrowUp') ? -1
    : (e.key === 'ArrowRight' || e.key === 'ArrowDown') ? 1 : 0;
  if (!direction) return;
  e.preventDefault();
  moveKeyboardSort(direction);
}

function moveKeyboardSort(direction) {
  const { card, grid } = keyboardSort;
  const cards = gridAppCards(grid);
  const current = cards.indexOf(card);
  const targetIndex = Math.max(0, Math.min(cards.length - 1, current + direction));
  if (targetIndex === current) {
    announceReorder(t(direction < 0 ? 'reorder.first' : 'reorder.last'));
    return;
  }
  const target = cards[targetIndex];
  flip(grid, () => {
    if (direction < 0) grid.insertBefore(card, target);
    else grid.insertBefore(card, target.nextSibling);
  });
  card.focus({ preventScroll: true });
  announceReorder(t('reorder.moved', {
    name: findApp(card.dataset.key)?.name || t('common.application'),
    position: targetIndex + 1,
    count: cards.length,
  }));
}

function finishKeyboardSort(commit) {
  const session = keyboardSort;
  keyboardSort = null;
  if (!commit) {
    const byId = new Map(gridAppCards(session.grid)
      .map(card => [card.dataset.key, card]));
    for (const id of session.originalIds) {
      const card = byId.get(id);
      if (card) session.grid.appendChild(card);
    }
  }
  session.card.classList.remove('keyboard-sorting');
  session.card.focus({ preventScroll: true });
  if (commit) {
    persistGridOrder(gridAppCards(session.grid).map(card => card.dataset.key));
    announceReorder(t('reorder.saved'));
  } else {
    announceReorder(t('reorder.canceled'));
  }
}

export function renderLaunchpad(apps, firstRender) {
  if (drag || keyboardSort) return;  // 排序中轮询不打乱 DOM
  const language = getLanguage();
  const languageChanged = language !== renderedLanguage;
  const svcs = apps.filter(a => (a.kind || 'service') !== 'task');
  const tasks = apps.filter(a => a.kind === 'task');
  const addSvc = $('#addSvcCard');
  const addTask = $('#addTaskCard');
  addSvc.remove();
  addTask.remove();
  reconcile(svcGrid, svcs, a => a.id, createAppCard, updateAppCard, firstRender);
  svcGrid.prepend(addSvc);                  // 新增入口始终优先可见
  reconcile(taskGrid, tasks, a => a.id, createAppCard, updateAppCard, firstRender);
  taskGrid.prepend(addTask);                // 批处理新增入口始终优先可见
  renderLpKpi(apps, svcs, tasks);
  latestSvcs = svcs;
  latestTasks = tasks;
  syncSvcFilterUI();
  syncTaskFilterUI();
  setText($('#svcSecCount'), svcs.length ? String(svcs.length) : '');
  setText($('#taskSecCount'), tasks.length ? String(tasks.length) : '');
  if (languageChanged && diagCurrentApp) {
    diagCurrentApp = apps.find(app => app.id === diagCurrentApp.id) || diagCurrentApp;
    renderPortDiagnostic(diagCurrentApp);
  }
  if (languageChanged && appDiagApp) {
    appDiagApp = apps.find(app => app.id === appDiagApp.id) || appDiagApp;
    renderAppDiagnosis(appDiagApp, appDiagResponse, appDiagResponse === null);
  }
  renderedLanguage = language;
}

function syncSvcFilterUI() {
  renderFilterChips($('#svcFilter'), SVC_FILTERS, latestSvcs, svcFilter, matchSvcFilter,
    f => { svcFilter = f; syncSvcFilterUI(); });
  applyGridFilter(svcGrid, latestSvcs, matchSvcFilter, svcFilter);
}
function syncTaskFilterUI() {
  renderFilterChips($('#taskFilter'), TASK_FILTERS, latestTasks, taskFilter, matchTaskFilter,
    f => { taskFilter = f; syncTaskFilterUI(); });
  applyGridFilter(taskGrid, latestTasks, matchTaskFilter, taskFilter);
}

/* ---------------- 启动台 KPI ---------------- */
function renderLpKpi(apps, svcs, tasks) {
  const running = apps.filter(a => a.running).length;
  setKpi($('#lpStatApps'), String(apps.length));
  setText($('#lpStatAppsSub'), t('overview.runningStopped', {
    running,
    stopped: apps.length - running,
  }));
  setKpi($('#lpStatRunning'), String(running));
  setKpi($('#lpStatTasks'), String(tasks.length));
  const runningTasks = tasks.filter(a => a.running).length;
  setText($('#lpStatTasksSub'), runningTasks
    ? t('overview.runningTasks', { count: runningTasks }) : t('common.idle'));
  const warn = apps.filter(a => a.portOccupied).length;
  setKpi($('#lpStatWarn'), String(warn));
  $('#lpStatWarn').classList.toggle('bad', warn > 0);
  setText($('#lpStatWarnSub'), t(warn
    ? 'common.needsAttention' : 'common.noAttentionNeeded'));
  /* 与「服务监控」同口径：我的服务负载合计 */
  let cpuSum = 0, memSum = 0;
  for (const s of ((state.data && state.data.services) || [])) {
    if (s.group !== 'mine' || s.hidden) continue;
    cpuSum += s.cpu || 0;
    memSum += s.mem || 0;
  }
  setKpiUnit($('#lpStatCpu'), cpuSum.toFixed(1), '%');
  setKpiUnit($('#lpStatMem'), memSum.toFixed(1), '%');
  setText($('#lpStatCpuSub'), t('overview.loadLevel', { level: loadLevel(cpuSum) }));
  setText($('#lpStatMemSub'), t('overview.memoryLevel', { level: loadLevel(memSum) }));
}

function loadLevel(pct) {
  return t(pct >= 80 ? 'common.tooHigh' : pct >= 50 ? 'common.high' : 'common.normal');
}

/* ---------------- 分区过滤芯片 ---------------- */
const SVC_FILTERS = [['all', 'filter.all'], ['running', 'filter.running'],
  ['stopped', 'filter.stopped'], ['error', 'filter.error']];
const TASK_FILTERS = [['all', 'filter.all'], ['running', 'filter.running'],
  ['succeeded', 'filter.succeeded'], ['failed', 'filter.failed'],
  ['canceled', 'filter.canceled']];
let svcFilter = 'all', taskFilter = 'all';
/* 芯片按钮只创建一次，点击时必须读取当轮数据而不是首次渲染的闭包快照 */
let latestSvcs = [], latestTasks = [];
let renderedLanguage = getLanguage();

function svcHasError(app) {
  if (app.portConflict || app.portOccupied || hasPortMismatch(app)) return true;
  if (!app.running && app.health && app.health.blocking) return true;
  if (!app.running && app.lastExit) {
    const isTask = (app.kind || 'service') === 'task';
    return isTask ? taskExitStatus(app.lastExit) === 'failed'
      : app.lastExit.code !== 0;
  }
  return false;
}
function matchSvcFilter(app, filter) {
  if (filter === 'running') return !!app.running;
  if (filter === 'stopped') return !app.running;
  if (filter === 'error') return svcHasError(app);
  return true;
}
function matchTaskFilter(app, filter) {
  if (filter === 'running') return !!app.running;
  if (filter === 'all') return true;
  if (app.running || !app.lastExit) return false;
  const status = taskExitStatus(app.lastExit);
  if (filter === 'canceled') return status === 'canceled' || status === 'stopped';
  return status === filter;
}

function renderFilterChips(row, defs, apps, active, match, onPick) {
  if (!row) return;
  if (row._sig !== defs) {
    row.replaceChildren();
    row._sig = defs;
    row._btns = new Map();
    for (const [key, labelKey] of defs) {
      const btn = el('button', 'fchip');
      btn.type = 'button';
      const text = el('span');
      text.textContent = t(labelKey);
      const count = el('span', 'fc-n');
      btn.append(text, count);
      btn.addEventListener('click', () => onPick(key));
      row.appendChild(btn);
      row._btns.set(key, { btn, text, count, labelKey });
    }
  }
  for (const [key] of defs) {
    const item = row._btns.get(key);
    item.btn.classList.toggle('active', key === active);
    item.btn.setAttribute('aria-pressed', String(key === active));
    setText(item.text, t(item.labelKey));
    setText(item.count, String(apps.filter(a => match(a, key)).length));
  }
}

function applyGridFilter(grid, apps, match, filter) {
  if (!grid) return;
  const byId = new Map(apps.map(a => [a.id, a]));
  for (const card of grid.querySelectorAll('.app-card[data-key]')) {
    const app = byId.get(card.dataset.key);
    card.hidden = app ? !match(app, filter) : false;
  }
}
