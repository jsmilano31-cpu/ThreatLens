const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { simulateRules, buildReport } = require('../public/static/app.js');

// Use real scanner output to verify that browser calculations follow Python rules.
const python = process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python';
const cases = JSON.parse(execFileSync(python, ['-c', `
import json
from app import EXAMPLES
from scanner import assess_url
print(json.dumps([dict(assess_url(item['url']), analysis_mode='demo', stats=None,
    notice='Local only', virustotal_status='not_requested') for item in EXAMPLES]))
`], { cwd: require('node:path').resolve(__dirname, '..'), encoding: 'utf8' }));

function deepFreeze(value) {
  Object.freeze(value);
  Object.values(value).forEach(child => { if (child && typeof child === 'object') deepFreeze(child); });
  return value;
}

test('all examples initially match their original score and all-off becomes zero', () => {
  for (const analysis of cases) {
    assert.equal(simulateRules(analysis.reasons).score, analysis.score);
    assert.equal(simulateRules(analysis.reasons).level, analysis.level);
    assert.equal(simulateRules(analysis.reasons, analysis.reasons.map(rule => rule.id)).score, 0);
    // Reset is the same calculation with no excluded rules.
    assert.equal(simulateRules(analysis.reasons, []).score, analysis.score);
  }
});

test('cap applies after summing: excluding HTTP from 105 raw points leaves 85', () => {
  const high = cases[2];
  assert.equal(high.reasons.reduce((sum, rule) => sum + rule.points, 0), 105);
  const simulation = simulateRules(high.reasons, ['http']);
  assert.equal(simulation.score, 85);
  assert.equal(simulation.level, 'high');
  assert.deepEqual(simulation.disabled_rule_ids, ['http']);
  assert.ok(!simulation.enabled_rule_ids.includes('http'));
});

test('simulation matches every subset of actual rules and threshold boundaries', () => {
  const rules = cases[2].reasons;
  for (let mask = 0; mask < 2 ** rules.length; mask++) {
    const disabled = rules.filter((rule, index) => mask & (1 << index)).map(rule => rule.id);
    const expected = Math.min(100, rules.filter(rule => !disabled.includes(rule.id)).reduce((sum, rule) => sum + rule.points, 0));
    const simulation = simulateRules(rules, disabled);
    assert.equal(simulation.score, expected);
    assert.equal(simulation.level, expected >= 70 ? 'high' : expected >= 40 ? 'medium' : 'low');
  }
  for (const [points, level] of [[0, 'low'], [39, 'low'], [40, 'medium'], [69, 'medium'], [70, 'high'], [100, 'high']]) {
    assert.equal(simulateRules([{ id: 'boundary', points }]).level, level);
  }
});

test('report serializes original evidence, vendor availability, and separate simulation', () => {
  const analysis = deepFreeze(cases[2]);
  const report = JSON.parse(JSON.stringify(buildReport(analysis, ['http'])));
  assert.equal(report.original.score, 100);
  assert.equal(report.simulation.score, 85);
  assert.equal(report.url, analysis.url);
  assert.equal(report.analyzed_at, analysis.analyzed_at);
  assert.deepEqual(report.components, analysis.components);
  assert.deepEqual(report.original.rules, analysis.reasons);
  assert.equal(report.virustotal.status, 'not_requested');
  assert.equal(report.virustotal.stats, null);
  assert.equal(report.analysis_mode, 'demo');
  assert.ok(!Number.isNaN(Date.parse(report.exported_at)));
  assert.equal(analysis.score, 100);
});

test('export preserves completed and unavailable VirusTotal evidence', () => {
  for (const [status, stats, notice] of [['completed', { malicious: 2, suspicious: 1 }, null],
                                     ['unavailable', null, 'Rate limit reached']]) {
    const analysis = deepFreeze({ ...cases[1], analysis_mode: 'virustotal', virustotal_status: status, stats, notice });
    const report = buildReport(analysis, ['http']);
    assert.deepEqual(report.virustotal, { status, stats, notice });
    assert.equal(report.original.score, analysis.score);
    assert.equal(report.simulation.score, 20);
  }
});

// Minimal DOM adapter exercises event wiring without a browser dependency.
function previewDOM(analysis) {
  const { runInNewContext } = require('node:vm');
  const { readFileSync } = require('node:fs');
  function element(properties = {}) {
    return Object.assign({ dataset: {}, hidden: true, checked: true, textContent: '', innerHTML: '',
      handlers: {}, children: [],
      addEventListener(type, handler) { this.handlers[type] = handler; },
      fire(type, event = {}) { this.handlers[type](event); },
      append(child) { this.children.push(child); },
      click() { this.clicked = true; },
      remove() { this.removed = true; },
    }, properties);
  }
  const controls = new Map();
  for (const id of ['simulator', 'simulation-score', 'simulation-verdict', 'simulation-summary',
                    'reset-simulation', 'download-report', 'report-status']) controls.set('#' + id, element());
  if (analysis) controls.set('#analysis-data', element({ dataset: { analysis: JSON.stringify(analysis) } }));
  const checks = analysis ? analysis.reasons.map(rule => element({ value: rule.id })) : [];
  const buttons = ['scan', 'local'].map(value => element({ name: 'action', value, disabled: false, innerHTML: value }));
  const form = element({ dataset: { busy: 'Working' },
    querySelector() { return buttons[0]; }, querySelectorAll() { return buttons; } });
  let downloaded;
  const created = [];
  const document = {
    body: element(),
    querySelector(selector) { return controls.get(selector) || null; },
    querySelectorAll(selector) {
      if (selector === 'form[data-busy]') return [form];
      if (selector === '[data-submit-choice]') return form.children;
      return checks;
    },
    createElement(tag) { const node = element({ tag }); created.push(node); return node; },
  };
  const window = element({ setTimeout(callback) { callback(); } });
  runInNewContext(readFileSync(require.resolve('../public/static/app.js'), 'utf8'), {
    document, window,
    Blob: class { constructor(parts) { downloaded = JSON.parse(parts.join('')); } },
    URL: { createObjectURL() { return 'blob:local-preview'; }, revokeObjectURL() {} },
  });
  return { controls, checks, buttons, form, window, created, getReport: () => downloaded };
}

test('UI event wiring toggles, resets, and downloads the current simulation', () => {
  const analysis = cases[2];
  const dom = previewDOM(analysis);
  assert.equal(dom.controls.get('#simulator').hidden, false);
  assert.equal(dom.controls.get('#download-report').hidden, false);
  const http = dom.checks.find(input => input.value === 'http');
  http.checked = false;
  http.fire('change');
  assert.equal(dom.controls.get('#simulation-score').textContent, 85);
  dom.controls.get('#download-report').fire('click');
  assert.equal(dom.getReport().simulation.score, 85);
  assert.equal(dom.getReport().original.score, 100);
  assert.equal(dom.created.find(node => node.tag === 'a').clicked, true);
  dom.checks.forEach(input => { input.checked = false; });
  http.fire('change');
  assert.equal(dom.controls.get('#simulation-score').textContent, 0);
  dom.controls.get('#reset-simulation').fire('click');
  assert.ok(dom.checks.every(input => input.checked));
  assert.equal(dom.controls.get('#simulation-score').textContent, 100);
  assert.equal(analysis.score, 100);
});

test('busy form keeps the chosen local action and restores buttons on Back', () => {
  const dom = previewDOM();
  dom.form.fire('submit', { submitter: dom.buttons[1] });
  assert.ok(dom.buttons.every(button => button.disabled));
  assert.equal(dom.form.children[0].name, 'action');
  assert.equal(dom.form.children[0].value, 'local');
  dom.window.fire('pageshow');
  assert.ok(dom.buttons.every(button => !button.disabled));
  assert.ok(dom.form.children[0].removed);
});
