'use strict';
/* ============================================================
   overlays.js — 浮层：确认框 / 应用编辑模态 / 日志抽屉
   ============================================================ */
import { $, el, setText, setChildren, icon, escapeHtml,
  post, put, del, act, toast, openLayer, closeLayer,
  GLYPHS, findApp, bumpMutationEpoch, state,
  isWindowsPlatform, defaultExecution, normalizeExecution,
  executionSignature, shellLabel, processIdentity } from './core.js';
import { t, getLanguage, subscribeLanguage, translateKnownText } from './i18n.js';

/* ---------------- DOM 引用 ---------------- */
const appModalMask = $('#appModalMask'), appModal = $('#appModal'), appModalTitle = $('#appModalTitle');
const fName = $('#fName'), fCmd = $('#fCmd'), fCwd = $('#fCwd'), fPort = $('#fPort');
const executionSettings = $('#executionSettings'), fEnvironment = $('#fEnvironment');
const shellField = $('#shellField'), fShell = $('#fShell');
const distroField = $('#distroField'), fDistro = $('#fDistro');
const executionHint = $('#executionHint');
const kindRow = $('#kindRow'), portField = $('#portField'), fCmdLabel = $('#fCmdLabel');
const btnPickScript = $('#btnPickScript'), btnPickCwd = $('#btnPickCwd');
const btnDetectProject = $('#btnDetectProject');
const detectPanel = $('#detectPanel'), detectSummary = $('#detectSummary');
const detectFiles = $('#detectFiles'), detectList = $('#detectList');
const iconFile = $('#iconFile'), btnPickIcon = $('#btnPickIcon'), btnRemoveIcon = $('#btnRemoveIcon');
const glyphGrid = $('#glyphGrid');
const iconPreview = $('#iconPreview');
const iconPreviewImg = $('#iconPreviewImg'), iconPreviewGlyph = $('#iconPreviewGlyph');
const iconPreviewTxt = $('#iconPreviewTxt');
const appearanceDetails = $('#appearanceDetails'), appearanceChevron = $('#appearanceChevron');
const appCancel = $('#appCancel'), appSave = $('#appSave');
const appStopEdit = $('#appStopEdit'), editRunningNotice = $('#editRunningNotice');

const confirmMask = $('#confirmMask'), confirmTitle = $('#confirmTitle'), confirmBody = $('#confirmBody');
const confirmCancel = $('#confirmCancel'), confirmOk = $('#confirmOk');

const drawerMask = $('#drawerMask'), logDrawer = $('#logDrawer');
const drawerTitle = $('#drawerTitle'), drawerClose = $('#drawerClose');
const logBody = $('#logBody'), logPre = $('#logPre');

const iconVer = new Map();   // appId → 图标版本号，上传/删除后刷新浏览器缓存
setChildren(appearanceChevron, icon('chevron-down', 16));
export function bumpIconVer(id) { iconVer.set(id, (iconVer.get(id) || 0) + 1); }
export function getIconVer(id) { return iconVer.get(id) || 0; }

/* 兼容尚未重启的旧后端；新后端会返回经过同样规则生成的 command。 */
function shellQuotePath(path) {
  return "'" + String(path).replace(/'/g, "'\"'\"'") + "'";
}
function fallbackScriptCommand(path, execution) {
  if (execution.environment === 'native' && isWindowsPlatform()) {
    const quoted = '"' + String(path).replace(/"/g, '""') + '"';
    const suffix = (String(path).match(/(\.[^./\\]+)$/) || [])[1]?.toLowerCase();
    if (suffix === '.py') return 'python ' + quoted;
    if (suffix === '.ps1') return 'powershell.exe -File ' + quoted;
    if (suffix === '.cmd' || suffix === '.bat') return quoted;
    return quoted;
  }
  const quoted = shellQuotePath(path);
  const suffix = (String(path).match(/(\.[^./]+)$/) || [])[1]?.toLowerCase();
  if (suffix === '.py') return 'python3 -- ' + quoted;
  if (suffix === '.zsh') return '/bin/zsh -- ' + quoted;
  return '/bin/bash -- ' + quoted;
}

/* ============================================================
   确认模态
   ============================================================ */
let confirmCb = null;
let confirmCancelCb = null;
export function openConfirm({ title, bodyHtml, okText = t('confirm.ok'),
                       tone = 'danger', onOk, onCancel = null }) {
  confirmTitle.textContent = title;
  confirmBody.innerHTML = bodyHtml;
  confirmOk.textContent = okText;
  confirmOk.classList.toggle('btn-stop', tone === 'danger');
  confirmOk.classList.toggle('btn-accent', tone === 'primary');
  confirmCb = onOk;
  confirmCancelCb = onCancel;
  openLayer(confirmMask, confirmCancel);
}
export function closeConfirm() {
  const onCancel = confirmCancelCb;
  closeLayer(confirmMask);
  confirmCb = null;
  confirmCancelCb = null;
  if (onCancel) onCancel();
}
confirmOk.addEventListener('click', () => {
  const cb = confirmCb;
  closeLayer(confirmMask);
  confirmCb = null;
  confirmCancelCb = null;
  if (cb) cb();
});
confirmCancel.addEventListener('click', closeConfirm);
confirmMask.addEventListener('mousedown', e => { if (e.target === confirmMask) closeConfirm(); });

/* ---------------- 结束进程确认 ---------------- */
export function confirmKill(svc) {
  const name = '<b>' + escapeHtml(svc.name || '') + '</b>';
  openConfirm({
    title: t('process.killTitle'),
    bodyHtml: t('process.killConfirm', { name }) +
      '<div class="confirm-detail mono">PID ' + escapeHtml(String(svc.pid)) +
      (svc.port ? ' · ' + t('common.port') + ' :' + escapeHtml(String(svc.port)) : '') + '</div>',
    okText: t('services.kill'),
    onOk: async () => requestProcessKill(svc),
  });
}

async function postDestructive(path, body, allowForcePrompt = false) {
  try {
    const result = await post(path, body);
    if (result && result.ok === false && !(allowForcePrompt && result.requiresForce)) {
      toast(translateKnownText(result.error) || t('errors.operationFailed'));
    }
    return result;
  } catch (error) {
    toast(t('errors.requestFailed', { message: error.message }));
    return null;
  }
}

function confirmForce({ title, bodyHtml, path, body }) {
  return new Promise(resolve => {
    openConfirm({
      title,
      bodyHtml,
      okText: t('process.forceKill'),
      tone: 'danger',
      onCancel: () => resolve({ ok: false, canceled: true, requiresForce: true }),
      onOk: async () => resolve(await postDestructive(path, body)),
    });
  });
}

/* 受管应用的普通停止绝不自动升级为强杀。只有后端返回
   requiresForce 后才展示第二个明确确认，确认后重新发送 {force:true}。 */
export async function requestManagedAppStop(app) {
  const id = app && app.id;
  if (!id) {
    toast(t('errors.identityMissing'));
    return null;
  }
  const path = '/api/apps/' + encodeURIComponent(id) + '/stop';
  const result = await postDestructive(path, {}, true);
  if (!result || result.ok !== false || !result.requiresForce) return result;
  const name = '<b>' + escapeHtml(app.name || t('common.application')) + '</b>';
  const isTask = (app.kind || 'service') === 'task';
  return confirmForce({
    title: t(isTask ? 'process.forceTaskTitle' : 'process.forceAppTitle'),
    bodyHtml: t('process.forceAppBody', { name }) +
      '<div class="confirm-detail">' + t('process.forceAppDetail') + '</div>',
    path,
    body: { force: true },
  });
}

export async function requestProcessKill(svc) {
  const identity = processIdentity(svc);
  if (!identity.instanceKey && identity.pid == null) {
    toast(t('errors.safeIdentityMissing'));
    return null;
  }
  const result = await postDestructive('/api/kill', { ...identity, force: false }, true);
  if (!result || result.ok !== false || !result.requiresForce) return result;
  const processName = '<b>' + escapeHtml(svc.name || t('common.process')) + '</b>';
  return confirmForce({
    title: t('process.forceProcessTitle'),
    bodyHtml: t('process.forceProcessBody', { name: processName }) +
      '<div class="confirm-detail mono">PID ' + escapeHtml(String(svc.pid || '—')) + '</div>' +
      '<div class="confirm-detail">' + t('process.forceProcessDetail') + '</div>',
    path: '/api/kill',
    body: { ...identity, force: true },
  });
}

/* ============================================================
   添加 / 编辑应用模态（图标库 + 上传）
   ============================================================ */
let editingAppId = null;
let editingAppOriginal = null;
let appSaving = false;
let pendingIcon = null;      // { blob, type, url }
let selectedGlyph = null;    // 选中的 Lucide 图标名
let removeStoredIcon = false; // 仅在保存成功后删除，取消编辑不触碰后端
let pendingAttach = null;     // 从服务监控添加时待认领的来源进程信息
let detectingProject = false; // 认领流程必须等项目命令识别完成后再允许保存
let platformReadyPromise = null;

export function buildGlyphGrid() {
  GLYPHS.forEach(g => {
    const b = el('button', 'glyph-btn');
    b.type = 'button';
    b.title = g;
    b.setAttribute('aria-label', t('appModal.chooseIconAria', { icon: g }));
    b.setAttribute('aria-pressed', 'false');
    b.dataset.glyph = g;
    b.appendChild(icon(g, 17));
    b.addEventListener('click', () => {
      const selecting = selectedGlyph !== g;
      selectedGlyph = selecting ? g : null;
      if (selecting) {
        clearPendingIcon();
        const app = editingAppId ? findApp(editingAppId) : null;
        if (app && app.icon) removeStoredIcon = true;
      }
      syncGlyphGrid();
      renderIconPreview();
    });
    glyphGrid.appendChild(b);
  });
}
function syncGlyphGrid() {
  for (const b of glyphGrid.children) {
    const selected = b.dataset.glyph === selectedGlyph;
    b.classList.toggle('sel', selected);
    b.setAttribute('aria-pressed', String(selected));
  }
}

function clearPendingIcon() {
  if (pendingIcon) URL.revokeObjectURL(pendingIcon.url);
  pendingIcon = null;
}
function setPendingIcon(file) {
  clearPendingIcon();
  selectedGlyph = null;
  removeStoredIcon = false;
  pendingIcon = { blob: file, type: file.type || 'image/png', url: URL.createObjectURL(file) };
  syncGlyphGrid();
  renderIconPreview();
}
/* 预览优先级：待上传图片 > 已上传图片 > glyph > 名称首字 */
function renderIconPreview() {
  const app = editingAppId ? findApp(editingAppId) : null;
  const showImg = pendingIcon || (!removeStoredIcon && app && app.icon);
  const glyph = selectedGlyph;
  if (showImg) {
    const v = getIconVer(app && app.id);
    iconPreviewImg.src = pendingIcon ? pendingIcon.url : app.icon + (v ? '?v=' + v : '');
    iconPreviewImg.hidden = false;
    iconPreviewGlyph.hidden = true;
    iconPreviewTxt.hidden = true;
  } else if (glyph && window.LUCIDE && window.LUCIDE[glyph]) {
    iconPreviewImg.hidden = true;
    iconPreviewGlyph.hidden = false;
    iconPreviewTxt.hidden = true;
    setChildren(iconPreviewGlyph, icon(glyph, 20));
  } else {
    iconPreviewImg.hidden = true;
    iconPreviewGlyph.hidden = true;
    iconPreviewTxt.hidden = false;
    const nm = fName.value.trim();
    iconPreviewTxt.textContent = nm ? [...nm][0].toUpperCase() : '?';
  }
  btnRemoveIcon.hidden = !(pendingIcon || selectedGlyph ||
    (!removeStoredIcon && app && (app.icon || app.glyph)));
}

let modalKind = 'service';
let detectRequestSeq = 0;
let detectedPortValue = null;
let lastDetectionResult = null;

function localizedCandidateText(value) {
  if (typeof value !== 'string') return value;
  const known = translateKnownText(value);
  if (known !== value || getLanguage() !== 'en') return known;
  const projectScript = value.match(/^项目脚本：(.+)$/);
  return projectScript ? t('candidate.projectScript', { name: projectScript[1] }) : value;
}

function availableShells() {
  const shells = state.platform && Array.isArray(state.platform.shells)
    ? state.platform.shells : [];
  const allowed = shells.filter(shell => ['auto', 'cmd', 'powershell'].includes(shell));
  return allowed.length ? [...new Set(allowed)] : ['auto', 'cmd', 'powershell'];
}

function installedDistros() {
  return state.platform && Array.isArray(state.platform.wslDistros)
    ? state.platform.wslDistros.filter(distro => distro && typeof distro === 'object')
    : [];
}

function setSelectOptions(select, options, selected) {
  select.replaceChildren();
  for (const item of options) {
    const option = document.createElement('option');
    option.value = item.value;
    option.textContent = item.label;
    option.disabled = !!item.disabled;
    if (item.title) option.title = item.title;
    select.appendChild(option);
  }
  if (options.some(item => item.value === selected && !item.disabled)) {
    select.value = selected;
  } else {
    const first = options.find(item => !item.disabled);
    select.value = first ? first.value : '';
  }
}

function readExecution() {
  if (executionSettings.hidden) return defaultExecution();
  if (fEnvironment.value === 'wsl') {
    return { environment: 'wsl', shell: 'posix', distro: fDistro.value || null };
  }
  return { environment: 'native', shell: fShell.value || 'auto', distro: null };
}

function renderExecutionFields(preferred) {
  const platform = state.platform;
  /* 只在已确认的 Windows 上展示；macOS 与未知/降级平台都隐藏。 */
  executionSettings.hidden = !isWindowsPlatform(platform);
  if (executionSettings.hidden) return;
  const execution = normalizeExecution(preferred || readExecution(), platform);
  const distros = installedDistros();
  const configuredDistro = execution.environment === 'wsl' ? execution.distro : null;
  const wslAvailable = distros.some(distro => distro && distro.available !== false && Number(distro.version) === 2);
  const wslOption = fEnvironment.querySelector('option[value="wsl"]');
  if (wslOption) {
    wslOption.disabled = !wslAvailable && !configuredDistro;
    wslOption.textContent = t(wslAvailable || configuredDistro
      ? 'platform.wsl2' : 'platform.wslUnavailableOption');
  }
  fEnvironment.value = execution.environment === 'wsl' && (wslAvailable || configuredDistro)
    ? 'wsl' : 'native';
  setSelectOptions(fShell, availableShells().map(shell => ({
    value: shell,
    label: shellLabel(shell),
  })), execution.shell);
  const distroOptions = distros.map(distro => {
    const version = Number(distro.version);
    const available = distro.available !== false && version === 2;
    const suffix = ' · ' + t(version === 1 ? 'platform.distroWsl1Unsupported'
      : !available ? 'platform.distroUnavailable'
        : distro.running ? 'platform.distroRunning' : 'platform.distroStopped');
    const value = distro.name || '';
    return {
      value,
      label: (value || t('platform.distroUnnamed')) + suffix,
      /* 保留现有应用的不可用/已删除配置，便于用户先修改
         名称或查看诊断；新建应用仍不能选择 WSL1/不可用项。 */
      disabled: !available && value !== configuredDistro,
      title: translateKnownText(distro.reason || ''),
    };
  });
  if (configuredDistro && !distroOptions.some(option => option.value === configuredDistro)) {
    distroOptions.unshift({
      value: configuredDistro,
      label: t('platform.distroNotInstalled', { distro: configuredDistro }),
      disabled: false,
      title: t('platform.distroReinstallHint'),
    });
  }
  setSelectOptions(fDistro, distroOptions, execution.distro || '');
  const isWsl = fEnvironment.value === 'wsl';
  shellField.hidden = isWsl;
  distroField.hidden = !isWsl;
  fShell.disabled = isWsl;
  fDistro.disabled = !isWsl;
  const wsl1Names = distros
    .filter(distro => Number(distro && distro.version) === 1)
    .map(distro => String(distro.name || t('platform.distroUnnamed')));
  const upgradeHint = wsl1Names.length
    ? t('platform.wsl1Help', { distros: wsl1Names.join(t('common.listSeparator')) })
    : '';
  const unavailableDetails = distros
    .filter(distro => Number(distro.version) === 2 && distro.available === false)
    .map(distro => String(distro.name || t('platform.distroUnnamed')) +
      (distro.reason ? ' (' + translateKnownText(String(distro.reason)) + ')' : ''));
  const availabilityHint = unavailableDetails.length
    ? t('platform.unavailableList', {
      distros: unavailableDetails.join(t('common.listSeparator')),
    })
    : (!distros.length && state.platform && state.platform.wslAvailable === false
      ? t('platform.noWsl2')
      : '');
  executionHint.textContent = (isWsl
    ? t('platform.wslHelp')
    : t('platform.nativeHelp')) +
    (availabilityHint ? ' ' + availabilityHint : '') +
    (upgradeHint ? ' ' + upgradeHint : '');
}

function readPortValue() {
  const raw = fPort.value.trim();
  if (!raw) return null;
  if (!/^\d+$/.test(raw)) return NaN;
  const value = Number(raw);
  return Number.isInteger(value) && value >= 1 && value <= 65535 ? value : NaN;
}

function resetDetection(clearAutoPort = false) {
  detectRequestSeq += 1;
  detectingProject = false;
  if (clearAutoPort && detectedPortValue != null &&
      fPort.value.trim() === String(detectedPortValue)) fPort.value = '';
  detectedPortValue = null;
  lastDetectionResult = null;
  btnDetectProject.disabled = false;
  btnPickCwd.disabled = false;
  detectPanel.hidden = true;
  detectList.replaceChildren();
  detectSummary.textContent = '';
  detectFiles.textContent = '';
}

function modalLifecycleChanged() {
  if (!editingAppOriginal) return false;
  const currentPort = modalKind === 'task' ? null
    : readPortValue();
  return fCmd.value.trim() !== (editingAppOriginal.command || '') ||
    (fCwd.value.trim() || null) !== (editingAppOriginal.cwd || null) ||
    currentPort !== (editingAppOriginal.port == null ? null : editingAppOriginal.port) ||
    modalKind !== (editingAppOriginal.kind || 'service') ||
    executionSignature(readExecution()) !== executionSignature(editingAppOriginal.execution);
}

function refreshEditSaveMode() {
  const running = !!(editingAppOriginal && editingAppOriginal.running);
  const needsStop = running && modalLifecycleChanged();
  const isTask = modalKind === 'task';
  const stopVerb = t(isTask ? 'appModal.stopTask' : 'appModal.stopService');
  editRunningNotice.hidden = !running;
  if (running) {
    setText(editRunningNotice, needsStop
      ? t('appModal.changesPreserved', { action: stopVerb })
      : t('appModal.runningCanStop', {
        kind: t(isTask ? 'common.task' : 'common.service'), action: stopVerb,
      }));
  }
  setText(appStopEdit, stopVerb);
  appStopEdit.hidden = !running;
  appStopEdit.disabled = appSaving;
  appSave.hidden = false;
  const willAttach = !editingAppId && pendingAttach && modalKind === 'service'
    && readPortValue() === pendingAttach.port
    && executionSignature(readExecution()) === executionSignature(pendingAttach.execution);
  setText(appSave, t(willAttach ? 'common.saveAndAttach' : 'common.save'));
  appSave.disabled = appSaving || needsStop || (willAttach && detectingProject);
  appSave.title = needsStop ? t('appModal.stopBeforeSave', { action: stopVerb })
    : (willAttach && detectingProject ? t('appModal.detectingReliableCommand') : '');
}

function setModalKind(kind) {
  modalKind = kind === 'task' ? 'task' : 'service';
  kindRow.querySelectorAll('.kind-btn').forEach(b => {
    const active = b.dataset.kind === modalKind;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', String(active));
  });
  portField.hidden = modalKind === 'task';
  fPort.disabled = modalKind === 'task';
  setText(fCmdLabel, t(modalKind === 'task' ? 'appModal.runCommand' : 'appModal.startCommand'));
  fName.placeholder = t(modalKind === 'task'
    ? 'appModal.nameTaskPlaceholder' : 'appModal.nameServicePlaceholder');
  fCmd.placeholder = modalKind === 'task'
    ? t('appModal.commandTaskPlaceholder')
    : t('appModal.commandServicePlaceholder');
  appModalTitle.textContent = t(modalKind === 'task'
    ? (editingAppId ? 'appModal.titleEditTask' : 'appModal.titleAddTask')
    : (editingAppId ? 'appModal.titleEditService' : 'appModal.titleAddService'));
  refreshEditSaveMode();
}
kindRow.querySelectorAll('.kind-btn').forEach(b =>
  b.addEventListener('click', () => setModalKind(b.dataset.kind)));

export function openAppModal(app, presetKind, focusAction = '') {
  if (!state.platform && platformReadyPromise) {
    return Promise.resolve(platformReadyPromise)
      .then(() => openAppModal(app, presetKind, focusAction));
  }
  editingAppId = app ? app.id : null;
  const attachPid = app && Number.isInteger(Number(app.attachPid))
    && Number(app.attachPid) > 0 ? Number(app.attachPid) : null;
  const attachInstanceKey = app && typeof app.attachInstanceKey === 'string'
    && app.attachInstanceKey ? app.attachInstanceKey : null;
  const attachWasRequested = !editingAppId && app && (attachInstanceKey || attachPid);
  const attachIdentity = attachWasRequested
    ? processIdentity({ instanceKey: attachInstanceKey, pid: attachPid }) : {};
  if (attachWasRequested && !attachIdentity.instanceKey && attachIdentity.pid == null) {
    toast(t('appModal.missingAttachIdentity'));
    return;
  }
  pendingAttach = attachWasRequested
    && Number.isInteger(Number(app.port))
    ? {
        pid: attachIdentity.pid || null,
        port: Number(app.port),
        instanceKey: attachIdentity.instanceKey || null,
        command: (app.command || '').trim(),
        execution: normalizeExecution(app.execution),
      }
    : null;
  editingAppOriginal = app ? {
    command: app.command || '', cwd: app.cwd || null,
    port: app.port == null ? null : app.port,
    kind: app.kind || 'service', running: !!app.running,
    execution: normalizeExecution(app.execution),
  } : null;
  resetDetection();
  clearPendingIcon();
  removeStoredIcon = false;
  selectedGlyph = (app && app.glyph) || null;
  fName.value = (app && app.name) || '';
  fCmd.value = (app && app.command) || '';
  fCwd.value = (app && app.cwd) || '';
  fPort.value = app && app.port != null ? app.port : '';
  renderExecutionFields(app && app.execution);
  [fName, fCmd, fCwd, fPort, fDistro].forEach(clearFieldError);
  setModalKind(presetKind || (app && app.kind) || 'service');
  appearanceDetails.open = !!(app && (app.icon || app.glyph));
  syncGlyphGrid();
  renderIconPreview();
  const focusTarget = focusAction === 'pick-script' ? btnPickScript
    : focusAction === 'pick-cwd' ? btnPickCwd
      : focusAction === 'edit-command' ? fCmd
        : app ? fName : (modalKind === 'task' ? btnPickScript : btnPickCwd);
  openLayer(appModalMask, focusTarget);
  /* 监听进程的 argv 往往只是框架子进程（如 next-server），不一定适合作为
     下次启动命令。打开认领表单时同时读取项目配置，让用户选择可靠命令。 */
  if (pendingAttach && fCwd.value.trim()) detectProject();
}
export function closeAppModal() {
  closeLayer(appModalMask);
  resetDetection();
  editingAppId = null;
  editingAppOriginal = null;
  clearPendingIcon();
  selectedGlyph = null;
  removeStoredIcon = false;
  pendingAttach = null;
}

function applyDetectedCandidate(candidate, option) {
  const previousAutoPort = detectedPortValue == null ? '' : String(detectedPortValue);
  const currentPort = fPort.value.trim();
  fCmd.value = candidate.command || '';
  clearFieldError(fCmd);
  setModalKind(candidate.kind || 'service');
  if (candidate.port != null) {
    if (!currentPort || currentPort === previousAutoPort) {
      fPort.value = String(candidate.port);
      detectedPortValue = candidate.port;
    } else {
      detectedPortValue = null;
    }
  } else {
    if (previousAutoPort && currentPort === previousAutoPort) fPort.value = '';
    detectedPortValue = null;
  }
  detectList.querySelectorAll('.detect-option').forEach(node => {
    const active = node === option;
    node.classList.toggle('selected', active);
    node.setAttribute('aria-pressed', String(active));
  });
  const portText = candidate.port != null && fPort.value === String(candidate.port)
    ? t('appModal.candidatePort', { port: candidate.port }) : '';
  refreshEditSaveMode();
  toast(t('appModal.candidateFilled', {
    label: localizedCandidateText(candidate.label), port: portText,
  }));
}

function renderDetection(result) {
  lastDetectionResult = result;
  const candidates = Array.isArray(result.candidates) ? result.candidates : [];
  detectPanel.hidden = false;
  detectList.replaceChildren();
  const files = Array.isArray(result.files) ? result.files : [];
  detectFiles.textContent = files.length ? t('appModal.filesRead', {
    files: files.join(t('common.listSeparator')),
  }) : '';
  if (!candidates.length) {
    detectSummary.textContent = t('appModal.noCandidates');
    const empty = el('p', 'detect-empty');
    empty.textContent = t('appModal.noCandidatesHint');
    detectList.appendChild(empty);
    return;
  }
  detectSummary.textContent = t('appModal.candidatesFound', { count: candidates.length });
  candidates.forEach((candidate, index) => {
    const option = el('button', 'detect-option');
    option.type = 'button';
    option.setAttribute('aria-pressed', 'false');
    const head = el('span', 'detect-option-head');
    const title = el('span', 'detect-option-title');
    title.textContent = localizedCandidateText(candidate.label || t('appModal.startProject'));
    head.appendChild(title);
    if (index === 0) {
      const recommended = el('span', 'detect-recommended');
      recommended.textContent = t('common.recommended');
      head.appendChild(recommended);
    }
    if (candidate.kind === 'task') {
      const kind = el('span', 'detect-kind');
      kind.textContent = t('common.task');
      head.appendChild(kind);
    }
    if (candidate.port != null) {
      const port = el('span', 'detect-port mono');
      port.textContent = ':' + candidate.port;
      head.appendChild(port);
    }
    const command = el('span', 'detect-command mono');
    command.textContent = candidate.command || '';
    const source = el('span', 'detect-source');
    source.textContent = localizedCandidateText(candidate.source || '');
    option.append(head, command, source);
    option.addEventListener('click', () => applyDetectedCandidate(candidate, option));
    detectList.appendChild(option);
  });
}

async function detectProject() {
  const cwd = fCwd.value.trim();
  if (!cwd) return fieldError(fCwd, t('appModal.chooseProjectFirst'));
  const requestSeq = ++detectRequestSeq;
  detectPanel.hidden = false;
  detectSummary.textContent = t('appModal.readingProject');
  detectFiles.textContent = '';
  detectList.replaceChildren();
  btnDetectProject.disabled = true;
  btnPickCwd.disabled = true;
  detectingProject = true;
  refreshEditSaveMode();
  try {
    const result = await act(post('/api/project/detect', {
      cwd,
      execution: readExecution(),
    }));
    if (requestSeq !== detectRequestSeq) return;
    if (!result || result.ok === false) {
      detectSummary.textContent = t('appModal.detectFailed');
      return;
    }
    if (!fName.value.trim() && result.name) {
      fName.value = result.name;
      renderIconPreview();
    }
    renderDetection(result);
    if (pendingAttach && !editingAppId &&
        fCmd.value.trim() === pendingAttach.command) {
      const candidates = Array.isArray(result.candidates) ? result.candidates : [];
      const index = candidates.findIndex(candidate =>
        candidate.kind !== 'task' && Number(candidate.port) === pendingAttach.port);
      if (index >= 0) {
        const option = detectList.querySelectorAll('.detect-option')[index];
        applyDetectedCandidate(candidates[index], option);
      }
    }
  } finally {
    if (requestSeq === detectRequestSeq) {
      detectingProject = false;
      btnDetectProject.disabled = false;
      btnPickCwd.disabled = false;
      refreshEditSaveMode();
    }
  }
}

function fieldError(input, msg) {
  toast(msg);
  input.classList.add('invalid');
  input.setAttribute('aria-invalid', 'true');
  input.focus();
}
function clearFieldError(input) {
  input.classList.remove('invalid');
  input.removeAttribute('aria-invalid');
}

async function stopEditingApp() {
  if (!editingAppId || !editingAppOriginal || !editingAppOriginal.running) return;
  appSaving = true;
  refreshEditSaveMode();
  const isTask = modalKind === 'task';
  toast(t('appModal.stoppingPreserve', {
    action: t(isTask ? 'appModal.stopTask' : 'appModal.stopService'),
  }));
  try {
    const result = await requestManagedAppStop({
      id: editingAppId,
      name: fName.value.trim() || t(isTask ? 'common.task' : 'common.service'),
      kind: modalKind,
    });
    await window.__poll();
    const latest = findApp(editingAppId);
    if ((result && result.ok !== false) || (latest && !latest.running)) {
      editingAppOriginal.running = false;
      toast(t('appModal.stoppedContinue', {
        result: t(isTask ? 'common.aborted' : 'common.stopped'),
      }));
    }
  } finally {
    appSaving = false;
    refreshEditSaveMode();
  }
}

function rememberSavedApp(app, id, body) {
  editingAppId = id;
  editingAppOriginal = {
    command: body.command,
    cwd: body.cwd,
    port: body.port,
    kind: body.kind,
    execution: body.execution,
    running: !!app.running,
  };
  setModalKind(body.kind);
}

async function saveApp() {
  const name = fName.value.trim();
  const command = fCmd.value.trim();
  if (!name) return fieldError(fName, t('appModal.nameRequired'));
  if (!command) return fieldError(
    fCmd, t(modalKind === 'task'
      ? 'appModal.runCommandRequired' : 'appModal.startCommandRequired'));
  const port = modalKind === 'task' ? null : readPortValue();
  if (Number.isNaN(port)) return fieldError(fPort, t('appModal.portInvalid'));
  const execution = readExecution();
  if (execution.environment === 'wsl' && !execution.distro) {
    return fieldError(fDistro, t('appModal.distroRequired'));
  }
  const body = {
    name,
    command,
    cwd: fCwd.value.trim() || null,
    port,
    glyph: selectedGlyph || null,
    kind: modalKind,
    execution,
  };
  const wasCreating = !editingAppId;
  const attachRequest = wasCreating && pendingAttach && modalKind === 'service'
    && port === pendingAttach.port
    && executionSignature(execution) === executionSignature(pendingAttach.execution)
    ? { ...pendingAttach } : null;
  if (attachRequest) {
    if (attachRequest.instanceKey) body.attachInstanceKey = attachRequest.instanceKey;
    else body.attachPid = attachRequest.pid;
  }
  appSaving = true;
  refreshEditSaveMode();
  try {
    const app = editingAppId
      ? await act(put('/api/apps/' + editingAppId, body))
      : await act(post('/api/apps', body));
    if (!app || app.ok === false) {
      if (app && app.requiresStop && editingAppOriginal) {
        editingAppOriginal.running = true;
        refreshEditSaveMode();
      }
      return;
    }
    const id = app.id || editingAppId;
    const attachSucceeded = !!(attachRequest && app.attached);
    if (attachSucceeded && app.cwd) {
      body.cwd = app.cwd;
      fCwd.value = app.cwd;
    }
    rememberSavedApp(
      attachSucceeded ? { ...app, running: true } : app,
      id,
      body,
    );
    if (pendingIcon && id) {
      try {
        const r = await fetch('/api/apps/' + id + '/icon', {
          method: 'POST',
          headers: { 'Content-Type': pendingIcon.type },
          body: pendingIcon.blob,
        });
        const j = await r.json();
        if (!r.ok || (j && j.ok === false)) {
          toast(translateKnownText(j && j.error) || t('appModal.iconUploadFailedSaved'));
          await window.__poll();
          return;
        }
        bumpIconVer(id);
        bumpMutationEpoch();   // 原生 fetch 不经过 req，手动作废在途旧快照
      } catch (e) {
        toast(t('appModal.iconUploadFailed', { message: e.message }));
        await window.__poll();
        return;
      }
    } else if (removeStoredIcon && id) {
      const result = await act(del('/api/apps/' + id + '/icon'));
      if (!result || result.ok === false) {
        toast(t('appModal.iconRemoveFailed'));
        await window.__poll();
        return;
      }
      removeStoredIcon = false;
      bumpIconVer(id);
    }
    closeAppModal();
    await window.__poll();
    if (attachSucceeded) toast(t('appModal.attached'));
  } finally {
    appSaving = false;
    refreshEditSaveMode();
  }
}

export function initAppModal({ onAddService, onAddTask, platformReady }) {
  platformReadyPromise = platformReady || Promise.resolve(state.platform);
  const openWhenReady = (app, kind) => Promise.resolve(platformReady)
    .finally(() => openAppModal(app, kind));
  onAddService.addEventListener('click', () => openWhenReady(null, 'service'));
  onAddTask.addEventListener('click', () => openWhenReady(null, 'task'));
  appCancel.addEventListener('click', closeAppModal);
  appSave.addEventListener('click', saveApp);
  appStopEdit.addEventListener('click', stopEditingApp);
  appModalMask.addEventListener('mousedown', e => { if (e.target === appModalMask) closeAppModal(); });

  /* 选择批处理脚本：自动填命令 / 工作目录 / 名称 */
  btnPickScript.addEventListener('click', async () => {
    btnPickScript.disabled = true;
    try {
      const execution = readExecution();
      const r = await act(post('/api/pick', {
        what: 'script', execution, language: getLanguage(),
      }));
      if (!r || r.canceled || !r.path) return;  // 取消或失败均静默
      const p = r.path;
      fCmd.value = r.command || fallbackScriptCommand(p, execution);
      const separatorIndex = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
      const dir = p.slice(0, separatorIndex);
      if (dir && !fCwd.value.trim()) fCwd.value = dir;
      if (!fName.value.trim()) {
        const base = p.split(/[\\/]/).pop()
          .replace(/\.(command|sh|bash|zsh|py|ps1|cmd|bat)$/i, '');
        if (base) fName.value = base;
      }
      fCmd.classList.remove('invalid');
      refreshEditSaveMode();
      detectList.querySelectorAll('.detect-option').forEach(node => {
        node.classList.remove('selected');
        node.setAttribute('aria-pressed', 'false');
      });
      toast(t('appModal.scriptCommandGenerated'));
    } finally {
      btnPickScript.disabled = false;
    }
  });

  /* 浏览工作目录（当前执行环境对应的原生 / WSL 选择流程） */
  btnPickCwd.addEventListener('click', async () => {
    btnPickCwd.disabled = true;
    try {
      const r = await act(post('/api/pick', {
        what: 'dir', execution: readExecution(), language: getLanguage(),
      }));
      if (r && !r.canceled && r.path) {
        fCwd.value = r.path;
        fCwd.classList.remove('invalid');
        refreshEditSaveMode();
        await detectProject();
      }
    } finally {
      btnPickCwd.disabled = false;
    }
  });
  btnDetectProject.addEventListener('click', detectProject);
  fEnvironment.addEventListener('change', () => {
    renderExecutionFields(readExecution());
    resetDetection(true);
    refreshEditSaveMode();
  });
  fShell.addEventListener('change', () => {
    resetDetection(true);
    refreshEditSaveMode();
  });
  fDistro.addEventListener('change', () => {
    clearFieldError(fDistro);
    resetDetection(true);
    refreshEditSaveMode();
  });
  fCwd.addEventListener('input', () => resetDetection(true));
  [fName, fCmd, fCwd, fPort].forEach(input =>
    input.addEventListener('input', () => {
      clearFieldError(input);
      refreshEditSaveMode();
    }));

  /* 图标：上传 / 粘贴 / 清除 */
  btnPickIcon.addEventListener('click', () => iconFile.click());
  iconFile.addEventListener('change', () => {
    const f = iconFile.files && iconFile.files[0];
    if (f) {
      if (!/^image\/(png|jpeg|webp)$/.test(f.type)) toast(t('appModal.imageTypesOnly'));
      else if (f.size > 5 * 1024 * 1024) toast(t('appModal.imageTooLarge'));
      else setPendingIcon(f);
    }
    iconFile.value = '';
  });
  appModal.addEventListener('paste', e => {
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (const it of items) {
      if (it.type && /^image\/(png|jpeg|webp)$/.test(it.type)) {
        const f = it.getAsFile();
        if (f) {
          if (f.size > 5 * 1024 * 1024) toast(t('appModal.imageTooLarge'));
          else {
            setPendingIcon(f);
            toast(t('appModal.imagePasted'));
          }
          e.preventDefault();
          break;
        }
      }
    }
  });
  btnRemoveIcon.addEventListener('click', () => {
    clearPendingIcon();
    selectedGlyph = null;
    syncGlyphGrid();
    if (editingAppId) {
      const a = findApp(editingAppId);
      removeStoredIcon = !!(a && a.icon);
    }
    renderIconPreview();
  });
  fName.addEventListener('input', renderIconPreview);
  /* 非 textarea 字段回车直接保存 */
  [fName, fCwd, fPort].forEach(inp =>
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') saveApp(); }));
}

/* ============================================================
   日志抽屉
   ============================================================ */
let logTimer = null;
let logAppId = null;
let logRequestSeq = 0;
let logController = null;
let logIsConsole = false;
let logAppName = '';
let logAwaitingFirstLoad = false;
let logShowingLoadError = false;

function logEndpoint(appId) {
  return logIsConsole ? '/api/console/log?tail=300'
    : '/api/apps/' + appId + '/logs?tail=300';
}

export function openLogs(app) {
  const name = app.name || '';
  openLogDrawer(app.id, t('logs.appDrawer', { name }), name);
}
export function openConsoleLog() {
  openLogDrawer('console', t('logs.consoleDrawer'));
}
function openLogDrawer(appId, title, appName = '') {
  closeLogs();
  logAppId = appId;
  logAppName = appName;
  logIsConsole = appId === 'console';
  const requestSeq = ++logRequestSeq;
  drawerTitle.textContent = title;
  logPre.textContent = t('logs.loading');
  logAwaitingFirstLoad = true;
  logShowingLoadError = false;
  logBody.setAttribute('aria-busy', 'true');
  openLayer(logDrawer, drawerClose);
  drawerMask.classList.add('open');
  drawerMask.setAttribute('aria-hidden', 'false');
  fetchLogs(appId, requestSeq);
}
async function fetchLogs(appId, requestSeq) {
  if (!logAppId || logAppId !== appId || requestSeq !== logRequestSeq) return;
  const controller = new AbortController();
  logController = controller;
  try {
    const r = await fetch(logEndpoint(appId), {
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    if (logAppId !== appId || requestSeq !== logRequestSeq) return;
    const firstLoad = logAwaitingFirstLoad;
    logAwaitingFirstLoad = false;
    logShowingLoadError = false;
    const nearBottom = firstLoad ||
      logBody.scrollHeight - logBody.scrollTop - logBody.clientHeight < 48;
    const text = j.text || '';
    /* 增量追加新行：全量重写会打断用户选区并让滚动位置漂移。 */
    const previous = firstLoad ? '' : logPre.textContent;
    if (previous && text.startsWith(previous)) {
      logPre.append(document.createTextNode(text.slice(previous.length)));
    } else {
      logPre.textContent = text;
    }
    logBody.setAttribute('aria-busy', 'false');
    if (nearBottom) requestAnimationFrame(() => {
      if (logAppId === appId && requestSeq === logRequestSeq) {
        logBody.scrollTop = logBody.scrollHeight;
      }
    });
  } catch (e) {
    if (e.name !== 'AbortError' && logAppId === appId && requestSeq === logRequestSeq) {
      if (logAwaitingFirstLoad) {
        logPre.textContent = t('logs.loadFailed');
        logAwaitingFirstLoad = false;
        logShowingLoadError = true;
      }
      logBody.setAttribute('aria-busy', 'false');
    }
  } finally {
    if (logController === controller) logController = null;
    if (!document.hidden && logAppId === appId && requestSeq === logRequestSeq) {
      logTimer = setTimeout(() => fetchLogs(appId, requestSeq), 1500);
    }
  }
}
export function closeLogs() {
  logRequestSeq += 1;
  if (logTimer) { clearTimeout(logTimer); logTimer = null; }
  if (logController) { logController.abort(); logController = null; }
  logAppId = null;
  logAppName = '';
  logAwaitingFirstLoad = false;
  logShowingLoadError = false;
  logBody.setAttribute('aria-busy', 'false');
  closeLayer(logDrawer);
  drawerMask.classList.remove('open');
  drawerMask.setAttribute('aria-hidden', 'true');
}
export function initLogDrawer() {
  drawerClose.addEventListener('click', closeLogs);
  drawerMask.addEventListener('click', closeLogs);
  document.addEventListener('visibilitychange', () => {
    if (!logAppId) return;
    if (document.hidden) {
      logRequestSeq += 1;
      if (logTimer) { clearTimeout(logTimer); logTimer = null; }
      if (logController) { logController.abort(); logController = null; }
    } else {
      fetchLogs(logAppId, ++logRequestSeq);
    }
  });
}

/* Keep an already-open editor/log drawer coherent when the header switch is
   used. Confirm dialogs make the background inert, so they cannot be toggled
   mid-confirmation and need no risky reconstruction. */
subscribeLanguage(() => {
  for (const button of glyphGrid.children) {
    button.setAttribute('aria-label', t('appModal.chooseIconAria', {
      icon: button.dataset.glyph || '',
    }));
  }
  if (appModalMask.classList.contains('open')) {
    renderExecutionFields(readExecution());
    setModalKind(modalKind);
    if (detectingProject) detectSummary.textContent = t('appModal.readingProject');
    if (lastDetectionResult) {
      const selectedCommand = fCmd.value.trim();
      renderDetection(lastDetectionResult);
      const candidates = Array.isArray(lastDetectionResult.candidates)
        ? lastDetectionResult.candidates : [];
      const selectedIndex = candidates.findIndex(candidate =>
        String(candidate.command || '').trim() === selectedCommand);
      if (selectedIndex >= 0) {
        const option = detectList.querySelectorAll('.detect-option')[selectedIndex];
        if (option) {
          option.classList.add('selected');
          option.setAttribute('aria-pressed', 'true');
        }
      }
    }
  }
  if (logAppId) {
    drawerTitle.textContent = logIsConsole
      ? t('logs.consoleDrawer')
      : t('logs.appDrawer', { name: logAppName });
    if (logAwaitingFirstLoad) {
      logPre.textContent = t('logs.loading');
    } else if (logShowingLoadError) {
      logPre.textContent = t('logs.loadFailed');
    }
  }
});
