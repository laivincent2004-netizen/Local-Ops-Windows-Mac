'use strict';
/* ============================================================
   ports.js — 端口归一化纯函数（无 DOM 依赖）

   配置端口用于启动前校验，ports 才是运行中进程实际监听的端口。
   两者不一致时，所有“打开/复制”动作必须使用实际端口，避免给出失效链接。
   独立成模块供启动台 / 服务监控 / 命令面板复用，也可被 node 直接单测。
   ============================================================ */

export function normalizePort(value) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

export function configuredPort(app) {
  return normalizePort(app && app.port);
}

export function actualPorts(app) {
  const seen = new Set();
  for (const value of (app && Array.isArray(app.ports) ? app.ports : [])) {
    const port = normalizePort(value);
    if (port) seen.add(port);
  }
  return [...seen];
}

export function hasPortMismatch(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  return !!(app && app.running && configured && app.listening === false
    && actual.length && !actual.includes(configured));
}

export function preferredOpenPort(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  if (hasPortMismatch(app)) return actual[0] || null;
  if (configured && (!app || !app.running || app.listening !== false)) return configured;
  return actual[0] || configured;
}

export function displayedPorts(app) {
  const configured = configuredPort(app);
  const actual = actualPorts(app);
  if (app && app.running && actual.length) {
    const preferred = preferredOpenPort(app);
    return [preferred, ...actual.filter(port => port !== preferred)];
  }
  return configured ? [configured] : actual;
}

export function portIsOpenable(app) {
  return !!(app && app.running && preferredOpenPort(app)
    && (!configuredPort(app) || app.listening !== false || hasPortMismatch(app)));
}
