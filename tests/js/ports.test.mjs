/* ports.js 纯函数行为测试（node --test，无 DOM 依赖）。
   覆盖配置端口 vs 实际监听端口的一致性判定，锁定三处 UI 共用的规则。 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizePort, configuredPort, actualPorts,
  hasPortMismatch, preferredOpenPort, displayedPorts,
  portIsOpenable } from '../../static/js/ports.js';

test('normalizePort 只接受 1-65535 的整数', () => {
  assert.equal(normalizePort(3000), 3000);
  assert.equal(normalizePort('3000'), 3000);
  assert.equal(normalizePort(0), null);
  assert.equal(normalizePort(-1), null);
  assert.equal(normalizePort(65536), null);
  assert.equal(normalizePort(1.5), null);
  assert.equal(normalizePort('abc'), null);
  assert.equal(normalizePort(null), null);
  assert.equal(normalizePort(undefined), null);
});

test('configuredPort 从 app.port 读取并归一化', () => {
  assert.equal(configuredPort({ port: 8080 }), 8080);
  assert.equal(configuredPort({ port: '8080' }), 8080);
  assert.equal(configuredPort({ port: 0 }), null);
  assert.equal(configuredPort({}), null);
  assert.equal(configuredPort(null), null);
});

test('actualPorts 去重并过滤非法值', () => {
  assert.deepEqual(actualPorts({ ports: [3000, 3001] }), [3000, 3001]);
  assert.deepEqual(actualPorts({ ports: [3000, 3000, '3001'] }), [3000, 3001]);
  assert.deepEqual(actualPorts({ ports: [0, 65536, 'x'] }), []);
  assert.deepEqual(actualPorts({}), []);
  assert.deepEqual(actualPorts(null), []);
});

test('hasPortMismatch：运行中且配置端口未被实际监听', () => {
  assert.equal(hasPortMismatch(
    { running: true, port: 3000, listening: false, ports: [9999] }), true);
  /* 配置端口也在实际列表里 → 不是错位 */
  assert.equal(hasPortMismatch(
    { running: true, port: 3000, listening: false, ports: [3000] }), false);
  /* 未运行不算错位 */
  assert.equal(hasPortMismatch(
    { running: false, port: 3000, listening: false, ports: [9999] }), false);
  /* 实际端口为空不算错位（无法判断） */
  assert.equal(hasPortMismatch(
    { running: true, port: 3000, listening: false, ports: [] }), false);
});

test('preferredOpenPort：运行中优先实际端口，未运行回退配置端口', () => {
  assert.equal(preferredOpenPort(
    { running: true, port: 3000, listening: false, ports: [9999] }), 9999);
  assert.equal(preferredOpenPort(
    { running: true, port: 3000, listening: true, ports: [3000] }), 3000);
  assert.equal(preferredOpenPort(
    { running: true, port: null, listening: true, ports: [5000] }), 5000);
  assert.equal(preferredOpenPort(
    { running: false, port: 3000 }), 3000);
  assert.equal(preferredOpenPort(
    { running: false, port: null, ports: [5000] }), 5000);
  assert.equal(preferredOpenPort({}), null);
});

test('displayedPorts：运行中把首选端口排最前', () => {
  assert.deepEqual(displayedPorts(
    { running: true, port: 3000, listening: false, ports: [9999, 3000] }),
    [9999, 3000]);
  assert.deepEqual(displayedPorts(
    { running: true, port: 3000, listening: true, ports: [3000, 3001] }),
    [3000, 3001]);
  assert.deepEqual(displayedPorts({ running: false, port: 3000 }), [3000]);
  assert.deepEqual(displayedPorts({ running: false, port: null }), []);
});

test('portIsOpenable：运行中且存在可打开端口', () => {
  assert.equal(portIsOpenable(
    { running: true, port: 3000, listening: true, ports: [3000] }), true);
  assert.equal(portIsOpenable(
    { running: true, port: 3000, listening: false, ports: [9999] }), true);
  /* 错位但无实际端口 → 不可打开 */
  assert.equal(portIsOpenable(
    { running: true, port: 3000, listening: false, ports: [] }), false);
  assert.equal(portIsOpenable({ running: false, port: 3000 }), false);
  assert.equal(portIsOpenable({}), false);
});
