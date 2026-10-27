/* Shared pure helpers keep simulation and exported findings in sync. */
(function () {
  'use strict';

  function simulateRules(reasons, disabledIds = []) {
    const disabled = new Set(disabledIds);
    const enabled = reasons.filter(reason => !disabled.has(reason.id));
    const score = Math.min(100, enabled.reduce((sum, reason) => sum + reason.points, 0));
    return {
      label: 'What-if simulation only; no URL changes or vendor rescan',
      score,
      level: score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low',
      enabled_rule_ids: enabled.map(reason => reason.id),
      disabled_rule_ids: reasons.filter(reason => disabled.has(reason.id)).map(reason => reason.id),
    };
  }

  function buildReport(analysis, disabledIds = []) {
    return {
      schema_version: 1,
      product: 'ThreatLens Link Detective',
      url: analysis.url,
      analyzed_at: analysis.analyzed_at,
      exported_at: new Date().toISOString(),
      analysis_mode: analysis.analysis_mode,
      components: analysis.components,
      original: { score: analysis.score, level: analysis.level, rules: analysis.reasons },
      virustotal: { status: analysis.virustotal_status, stats: analysis.stats, notice: analysis.notice },
      simulation: simulateRules(analysis.reasons, disabledIds),
      interpretation: 'Heuristic scores are indicators, not proof of a scam. Low scores and undetected verdicts do not guarantee safety.',
    };
  }

  // Node can exercise the same helpers without a browser or extra dependencies.
  if (typeof module !== 'undefined' && module.exports) module.exports = { simulateRules, buildReport };
  if (typeof document === 'undefined') return;

  const toggle = document.querySelector('#toggle-password');
  if (toggle) toggle.addEventListener('click', () => {
    const input = document.querySelector('#password');
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    toggle.textContent = visible ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', String(visible));
  });

  const busyButtons = new Map();
  document.querySelectorAll('form[data-busy]').forEach(form => {
    form.addEventListener('submit', event => {
      const button = event.submitter || form.querySelector('button[type="submit"]');
      // Disabled submitters aren't sent by browsers. Preserve the chosen action
      // before disabling buttons, including the local-only example selection.
      if (button && button.name) {
        const choice = document.createElement('input');
        choice.type = 'hidden';
        choice.name = button.name;
        choice.value = button.value;
        choice.dataset.submitChoice = 'true';
        form.append(choice);
      }
      form.querySelectorAll('button[type="submit"]').forEach(item => {
        busyButtons.set(item, item.innerHTML);
        item.disabled = true;
      });
      if (button) button.textContent = button.dataset.busy || form.dataset.busy;
    });
  });
  window.addEventListener('pageshow', () => {
    busyButtons.forEach((html, button) => { button.innerHTML = html; button.disabled = false; });
    busyButtons.clear();
    document.querySelectorAll('[data-submit-choice]').forEach(input => input.remove());
  });

  const payload = document.querySelector('#analysis-data');
  if (!payload) return;
  const analysis = JSON.parse(payload.dataset.analysis);
  const simulator = document.querySelector('#simulator');
  const checks = Array.from(document.querySelectorAll('#simulation-rules input[type="checkbox"]'));
  const disabledIds = () => checks.filter(input => !input.checked).map(input => input.value);
  const update = () => {
    const simulation = simulateRules(analysis.reasons, disabledIds());
    document.querySelector('#simulation-score').textContent = simulation.score;
    document.querySelector('#simulation-verdict').textContent = `${simulation.score}/100 · ${simulation.level[0].toUpperCase() + simulation.level.slice(1)} simulated risk`;
    document.querySelector('#simulation-summary').className = `simulation-summary ${simulation.level}`;
  };
  checks.forEach(input => input.addEventListener('change', update));
  document.querySelector('#reset-simulation').addEventListener('click', () => {
    checks.forEach(input => { input.checked = true; });
    update();
  });
  update();
  simulator.hidden = false;

  const download = document.querySelector('#download-report');
  download.hidden = false;
  download.addEventListener('click', () => {
    const report = buildReport(analysis, disabledIds());
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'ThreatLens-report.json';
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    document.querySelector('#report-status').textContent = 'JSON report downloaded with the original findings and current simulation.';
  });
}());
