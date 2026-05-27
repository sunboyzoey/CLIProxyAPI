package api

import (
	"bytes"
	"strings"
)

const managementPanelFaultCleanupMarker = "cpa-remove-faulty-auths-extension"

func injectManagementPanelExtensions(data []byte) []byte {
	if len(data) == 0 || bytes.Contains(data, []byte(managementPanelFaultCleanupMarker)) {
		return data
	}
	script := []byte(managementPanelFaultCleanupScript)
	lower := strings.ToLower(string(data))
	idx := strings.LastIndex(lower, "</body>")
	if idx < 0 {
		out := make([]byte, 0, len(data)+len(script))
		out = append(out, data...)
		out = append(out, script...)
		return out
	}
	out := make([]byte, 0, len(data)+len(script))
	out = append(out, data[:idx]...)
	out = append(out, script...)
	out = append(out, data[idx:]...)
	return out
}

const managementPanelFaultCleanupScript = `<script id="cpa-remove-faulty-auths-extension">
(function(){
  const buttonId = 'cpa-remove-faulty-auths-button';
  const prefix = 'enc::v1::';
  const keyBase = 'cli-proxy-api-webui::secure-storage';

  function decodeStored(raw) {
    if (!raw) return null;
    let text = raw;
    if (raw.startsWith(prefix)) {
      try {
        const keyText = keyBase + '|' + window.location.host + '|' + navigator.userAgent;
        const key = new TextEncoder().encode(keyText);
        const encoded = raw.slice(prefix.length);
        const bytes = Uint8Array.from(atob(encoded), function(ch) { return ch.charCodeAt(0); });
        for (let i = 0; i < bytes.length; i++) bytes[i] = bytes[i] ^ key[i % key.length];
        text = new TextDecoder().decode(bytes);
      } catch (err) {
        return null;
      }
    }
    try {
      return JSON.parse(text);
    } catch (err) {
      return text;
    }
  }

  function readStored(name) {
    try {
      return decodeStored(window.localStorage.getItem(name));
    } catch (err) {
      return null;
    }
  }

  function readStoredString(name) {
    const value = readStored(name);
    return typeof value === 'string' ? value.trim() : '';
  }

  function persistedState() {
    const raw = readStored('cli-proxy-auth');
    if (!raw || typeof raw !== 'object') return {};
    return raw.state && typeof raw.state === 'object' ? raw.state : raw;
  }

  function normalizeBase(value) {
    let base = String(value || '').trim();
    if (!base) base = window.location.origin;
    base = base.replace(/\/?v0\/management\/?$/i, '').replace(/\/+$/g, '');
    if (!/^https?:\/\//i.test(base)) base = 'http://' + base;
    return base;
  }

  function connectionInfo() {
    const state = persistedState();
    const apiBase = normalizeBase(readStoredString('apiBase') || readStoredString('apiUrl') || state.apiBase || window.location.origin);
    let managementKey = readStoredString('managementKey') || (typeof state.managementKey === 'string' ? state.managementKey.trim() : '');
    if (!managementKey) {
      managementKey = window.prompt('请输入管理密钥', '') || '';
    }
    return { apiBase, managementKey };
  }

  function shouldShow() {
    return String(window.location.hash || '').indexOf('/auth-files') >= 0;
  }

  function ensureButton() {
    let existing = document.getElementById(buttonId);
    if (!shouldShow()) {
      if (existing) existing.remove();
      return;
    }
    if (existing) return;
    const button = document.createElement('button');
    button.id = buttonId;
    button.type = 'button';
    button.textContent = '去除故障';
    button.title = '检查全部账号；401 和 429 直接删除';
    button.style.cssText = [
      'position:fixed',
      'right:24px',
      'bottom:24px',
      'z-index:2147483647',
      'height:38px',
      'padding:0 14px',
      'border-radius:8px',
      'border:1px solid #b91c1c',
      'background:#dc2626',
      'color:#fff',
      'font-size:14px',
      'font-weight:700',
      'box-shadow:0 10px 24px rgba(0,0,0,.18)',
      'cursor:pointer'
    ].join(';');
    button.addEventListener('mouseenter', function() { if (!button.disabled) button.style.background = '#b91c1c'; });
    button.addEventListener('mouseleave', function() { if (!button.disabled) button.style.background = '#dc2626'; });
    button.addEventListener('click', async function() {
      if (button.disabled) return;
      if (!window.confirm('将检查全部账号：401 和 429 会直接删除。是否继续？')) return;
      const info = connectionInfo();
      if (!info.managementKey.trim()) {
        window.alert('缺少管理密钥');
        return;
      }
      button.disabled = true;
      button.style.cursor = 'wait';
      button.style.opacity = '.78';
      button.textContent = '处理中...';
      try {
        const res = await fetch(info.apiBase + '/v0/management/auth-files/remove-faulty', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + info.managementKey.trim(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ concurrency: 16, reload_memory: true })
        });
        const text = await res.text();
        let data = {};
        try { data = text ? JSON.parse(text) : {}; } catch (err) {}
        if (!res.ok) {
          throw new Error(data.error || text || ('HTTP ' + res.status));
        }
        const checked = Number(data.checked || 0);
        const removed = Number(data.removed_401 || 0);
        const removed429 = Number(data.removed_429 || 0);
        const failed = Number(data.failed || 0);
        button.textContent = '已完成';
        window.alert('去除故障完成：检查 ' + checked + '，删除401 ' + removed + '，删除429 ' + removed429 + '，失败 ' + failed);
        window.location.reload();
      } catch (err) {
        window.alert('去除故障失败：' + (err && err.message ? err.message : String(err)));
        button.disabled = false;
        button.style.cursor = 'pointer';
        button.style.opacity = '1';
        button.style.background = '#dc2626';
        button.textContent = '去除故障';
      }
    });
    document.body.appendChild(button);
  }

  window.addEventListener('hashchange', ensureButton);
  window.addEventListener('load', ensureButton);
  new MutationObserver(ensureButton).observe(document.documentElement, { childList: true, subtree: true });
  ensureButton();
})();
</script>`
