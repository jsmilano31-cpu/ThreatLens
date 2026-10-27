const toggle = document.querySelector('#toggle-password');
if (toggle) toggle.addEventListener('click', () => {
  const input = document.querySelector('#password');
  const visible = input.type === 'password';
  input.type = visible ? 'text' : 'password';
  toggle.textContent = visible ? 'Hide' : 'Show';
  toggle.setAttribute('aria-pressed', String(visible));
});
document.querySelectorAll('form[data-busy]').forEach(form => {
  form.addEventListener('submit', () => {
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = form.dataset.busy;
  });
});
