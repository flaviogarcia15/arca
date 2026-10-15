/*
 * Arca — cofre de senhas local
 * JavaScript puro + Web Crypto API. Nenhuma dependência externa.
 *
 * Organização do arquivo:
 *   1. Constantes e utilitários
 *   2. Preferências (não sensíveis) e tema
 *   3. Criptografia (PBKDF2 + AES-256-GCM) e envelope do arquivo
 *   4. Validação/saneamento dos dados do cofre
 *   5. Acesso a arquivos (File System Access API + fallback)
 *   6. Gerador de senhas e estimativa de força
 *   7. Área de transferência
 *   8. Componentes de interface: ícones, toasts, modal, drawer
 *   9. Sessão: criar, abrir, desbloquear, salvar, bloquear
 *  10. Renderização das telas
 *  11. Formulários (credencial, projeto, configurações, gerador)
 *  12. Ações, atalhos e inicialização
 *
 * Regra de segurança: nenhuma senha, chave ou conteúdo descriptografado é
 * enviado ao console, ao localStorage, ao sessionStorage ou ao IndexedDB.
 */
(() => {
  'use strict';

  /* =========================================================================
   * 1. Constantes e utilitários
   * ====================================================================== */

  const FORMAT_ID = 'arca-vault';
  const FORMAT_VERSION = 1;
  const SCHEMA_VERSION = 1;
  const KDF_DEFAULT_ITERATIONS = 600000;
  const KDF_MIN_ITERATIONS = 100000;
  const KDF_MAX_ITERATIONS = 10000000;
  const KDF_ITERATION_CHOICES = [310000, 600000, 1000000, 2000000];
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const MAX_FILE_BYTES = 25 * 1024 * 1024;
  const MIN_MASTER_LENGTH = 10;
  const CLIPBOARD_CLEAR_MS = 30000;
  const AUTOSAVE_DELAY_MS = 800;
  const HISTORY_LIMIT = 5;

  const LIMITS = {
    name: 120, system: 120, url: 2048, username: 256, password: 1024,
    notes: 10000, projectName: 60, projectDesc: 280, vaultName: 60,
  };

  const CATEGORIES = [
    { id: 'login', label: 'Login', icon: 'key', color: 'blue' },
    { id: 'finance', label: 'Banco e finanças', icon: 'bank', color: 'green' },
    { id: 'dev', label: 'Desenvolvimento', icon: 'code', color: 'violet' },
    { id: 'infra', label: 'Infraestrutura', icon: 'server', color: 'orange' },
    { id: 'email', label: 'E-mail', icon: 'mail', color: 'teal' },
    { id: 'social', label: 'Redes sociais', icon: 'users', color: 'rose' },
    { id: 'other', label: 'Outros', icon: 'box', color: 'slate' },
  ];
  const CATEGORY_MAP = new Map(CATEGORIES.map((c) => [c.id, c]));

  const PROJECT_COLORS = [
    { id: 'slate', label: 'Grafite' }, { id: 'blue', label: 'Azul' },
    { id: 'teal', label: 'Verde-água' }, { id: 'green', label: 'Verde' },
    { id: 'amber', label: 'Âmbar' }, { id: 'orange', label: 'Laranja' },
    { id: 'rose', label: 'Rosa' }, { id: 'violet', label: 'Violeta' },
  ];
  const PROJECT_COLOR_IDS = PROJECT_COLORS.map((c) => c.id);
  const PROJECT_ICONS = [
    { id: 'folder', label: 'Pasta' }, { id: 'briefcase', label: 'Trabalho' },
    { id: 'code', label: 'Código' }, { id: 'server', label: 'Servidor' },
    { id: 'globe', label: 'Web' }, { id: 'home', label: 'Casa' },
    { id: 'cart', label: 'Compras' }, { id: 'bank', label: 'Finanças' },
    { id: 'users', label: 'Equipe' }, { id: 'rocket', label: 'Lançamento' },
  ];
  const PROJECT_ICON_IDS = PROJECT_ICONS.map((i) => i.id);

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);
  }

  function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function newId() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const b = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function debounce(fn, wait) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), wait);
    };
  }

  function normalizeText(value) {
    return String(value ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  }

  function plural(n, one, many) {
    return `${n.toLocaleString('pt-BR')} ${n === 1 ? one : many}`;
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1).replace('.', ',')} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1).replace('.', ',')} MB`;
  }

  const dateFormatter = new Intl.DateTimeFormat('pt-BR', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
  const relativeFormatter = new Intl.RelativeTimeFormat('pt-BR', { numeric: 'auto' });
  const RELATIVE_UNITS = [
    ['year', 31536000], ['month', 2592000], ['week', 604800],
    ['day', 86400], ['hour', 3600], ['minute', 60],
  ];

  function formatDate(iso) {
    const t = Date.parse(iso);
    return Number.isFinite(t) ? dateFormatter.format(t) : '—';
  }

  function relativeTime(iso) {
    const t = typeof iso === 'number' ? iso : Date.parse(iso);
    if (!Number.isFinite(t)) return '—';
    const seconds = (t - Date.now()) / 1000;
    if (Math.abs(seconds) < 45) return 'agora mesmo';
    for (const [unit, size] of RELATIVE_UNITS) {
      if (Math.abs(seconds) >= size || unit === 'minute') {
        return relativeFormatter.format(Math.round(seconds / size), unit);
      }
    }
    return '—';
  }

  /** Aceita apenas URLs http/https. Retorna null para qualquer outro esquema. */
  function toSafeUrl(raw) {
    const value = String(raw ?? '').trim();
    if (!value) return null;
    const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`;
    try {
      const url = new URL(candidate);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
      if (!url.hostname) return null;
      return url;
    } catch {
      return null;
    }
  }

  function displayUrl(url) {
    if (!url) return '';
    const path = url.pathname === '/' ? '' : url.pathname;
    return `${url.host}${path}`;
  }

  function slugify(value) {
    const slug = normalizeText(value).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    return slug.slice(0, 40) || 'cofre';
  }

  function timestampForFile(date = new Date()) {
    const p = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}-${p(date.getHours())}${p(date.getMinutes())}`;
  }

  class VaultError extends Error {
    constructor(code, cause) {
      super(code);
      this.name = 'VaultError';
      this.code = code;
      if (cause) this.cause = cause;
    }
  }

  const ERROR_MESSAGES = {
    'empty-file': 'O arquivo está vazio.',
    'not-json': 'O arquivo não é um cofre válido: o conteúdo não foi reconhecido.',
    'not-vault': 'Este arquivo não é um cofre do Arca.',
    'unsupported-version': 'Este cofre foi criado por uma versão incompatível do Arca.',
    'invalid-envelope': 'O arquivo do cofre está incompleto ou corrompido.',
    'decrypt-failed': 'Senha mestra incorreta ou arquivo alterado. Verifique e tente novamente.',
    'invalid-payload': 'O cofre foi aberto, mas os dados internos estão em formato inválido.',
    'too-large': 'O arquivo é grande demais para ser um cofre do Arca.',
    'read-failed': 'Não foi possível ler o arquivo. Verifique se ele ainda existe e tente novamente.',
    'write-failed': 'Não foi possível gravar o arquivo. Os dados continuam abertos aqui; tente salvar novamente ou use “Salvar como”.',
    'permission-denied': 'O navegador não concedeu permissão para gravar no arquivo.',
    'crypto-failed': 'Falha ao processar a criptografia neste navegador.',
  };

  function errorMessage(error, fallback = 'Ocorreu um erro inesperado.') {
    if (error instanceof VaultError) return ERROR_MESSAGES[error.code] || fallback;
    return fallback;
  }

  /** Registra erros técnicos sem nunca incluir dados sensíveis. */
  function reportError(context, error) {
    const code = error instanceof VaultError ? error.code : (error && error.name) || 'Error';
    console.warn(`[Arca] ${context}: ${code}`);
  }

  function isAbortError(error) {
    return error && (error.name === 'AbortError' || error.name === 'NotAllowedError' && /user/i.test(error.message || ''));
  }

  /* =========================================================================
   * 2. Preferências (somente dados NÃO sensíveis) e tema
   * ====================================================================== */

  const Prefs = (() => {
    const KEY = 'arca.prefs.v1';
    const defaults = {
      theme: 'system',
      autosave: true,
      autoLockMinutes: 15,
      clearClipboard: true,
      sort: 'name-asc',
      generator: { length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false },
    };
    const data = load();

    function sanitize(raw) {
      const out = structuredClone(defaults);
      if (!isPlainObject(raw)) return out;
      if (['system', 'light', 'dark'].includes(raw.theme)) out.theme = raw.theme;
      if (typeof raw.autosave === 'boolean') out.autosave = raw.autosave;
      if ([0, 5, 15, 30, 60].includes(raw.autoLockMinutes)) out.autoLockMinutes = raw.autoLockMinutes;
      if (typeof raw.clearClipboard === 'boolean') out.clearClipboard = raw.clearClipboard;
      if (['name-asc', 'name-desc', 'updated-desc', 'updated-asc'].includes(raw.sort)) out.sort = raw.sort;
      if (isPlainObject(raw.generator)) {
        const g = raw.generator;
        if (Number.isInteger(g.length) && g.length >= 8 && g.length <= 128) out.generator.length = g.length;
        for (const k of ['upper', 'lower', 'digits', 'symbols', 'avoidAmbiguous']) {
          if (typeof g[k] === 'boolean') out.generator[k] = g[k];
        }
        if (!out.generator.upper && !out.generator.lower && !out.generator.digits && !out.generator.symbols) {
          out.generator.lower = true;
        }
      }
      return out;
    }

    function load() {
      try {
        const raw = localStorage.getItem(KEY);
        return sanitize(raw ? JSON.parse(raw) : null);
      } catch {
        return structuredClone(defaults);
      }
    }

    return {
      get: (key) => structuredClone(data[key]),
      set(key, value) {
        data[key] = value;
        try { localStorage.setItem(KEY, JSON.stringify(data)); } catch { /* armazenamento indisponível */ }
      },
    };
  })();

  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function effectiveTheme() {
    const pref = Prefs.get('theme');
    if (pref === 'light' || pref === 'dark') return pref;
    return darkQuery.matches ? 'dark' : 'light';
  }

  function applyTheme() {
    const pref = Prefs.get('theme');
    const root = document.documentElement;
    if (pref === 'system') delete root.dataset.theme;
    else root.dataset.theme = pref;
    const effective = effectiveTheme();
    root.dataset.effectiveTheme = effective;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = effective === 'dark' ? '#0d0f13' : '#f5f6f8';
  }

  function toggleTheme() {
    Prefs.set('theme', effectiveTheme() === 'dark' ? 'light' : 'dark');
    applyTheme();
  }

  /* =========================================================================
   * 3. Criptografia e envelope do arquivo
   * ====================================================================== */

  function bytesToBase64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    if (typeof value !== 'string' || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
      throw new VaultError('invalid-envelope');
    }
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }

  const VaultCrypto = {
    randomBytes(length) {
      return crypto.getRandomValues(new Uint8Array(length));
    },

    /** PBKDF2-SHA-256 → chave AES-GCM de 256 bits, NÃO exportável. */
    async deriveKey(password, salt, iterations) {
      const passwordBytes = textEncoder.encode(password);
      try {
        const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
        return await crypto.subtle.deriveKey(
          { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
      } catch (error) {
        throw new VaultError('crypto-failed', error);
      } finally {
        passwordBytes.fill(0);
      }
    },

    /**
     * Dados adicionais autenticados (AAD): vinculam os metadados do envelope
     * ao texto cifrado. Qualquer alteração nos parâmetros invalida a tag GCM.
     */
    additionalData(header) {
      return textEncoder.encode([
        header.format, header.version, header.vaultId,
        header.kdf.name, header.kdf.hash, header.kdf.iterations, header.kdf.salt,
        header.cipher.name, header.cipher.keyLength, header.cipher.tagLength, header.cipher.iv,
      ].join('|'));
    },

    async seal(key, baseHeader, payload) {
      const iv = this.randomBytes(IV_BYTES); // IV novo a cada gravação
      const header = {
        ...baseHeader,
        cipher: { name: 'AES-GCM', keyLength: 256, tagLength: 128, iv: bytesToBase64(iv) },
      };
      const plaintext = textEncoder.encode(JSON.stringify(payload));
      try {
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, additionalData: this.additionalData(header), tagLength: 128 },
          key,
          plaintext,
        );
        return { ...header, ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
      } catch (error) {
        throw new VaultError('crypto-failed', error);
      } finally {
        plaintext.fill(0);
      }
    },

    async open(key, envelope) {
      const iv = base64ToBytes(envelope.cipher.iv);
      const ciphertext = base64ToBytes(envelope.ciphertext);
      let buffer;
      try {
        buffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, additionalData: this.additionalData(envelope), tagLength: 128 },
          key,
          ciphertext,
        );
      } catch {
        // Não diferenciamos "senha errada" de "arquivo adulterado": ambos falham na tag GCM.
        throw new VaultError('decrypt-failed');
      }
      const bytes = new Uint8Array(buffer);
      try {
        return JSON.parse(textDecoder.decode(bytes));
      } catch {
        throw new VaultError('invalid-payload');
      } finally {
        bytes.fill(0);
      }
    },

    async sha256Hex(text) {
      const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(text));
      return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
    },
  };

  function isIsoDate(value) {
    return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
  }

  /** Valida a estrutura do envelope ANTES de qualquer tentativa de descriptografia. */
  function parseEnvelope(text) {
    if (typeof text !== 'string' || !text.trim()) throw new VaultError('empty-file');
    let raw;
    try {
      raw = JSON.parse(text);
    } catch {
      throw new VaultError('not-json');
    }
    if (!isPlainObject(raw) || raw.format !== FORMAT_ID) throw new VaultError('not-vault');
    if (raw.version !== FORMAT_VERSION) throw new VaultError('unsupported-version');

    const { kdf, cipher } = raw;
    const valid = typeof raw.vaultId === 'string' && /^[A-Za-z0-9-]{8,64}$/.test(raw.vaultId)
      && isPlainObject(kdf) && kdf.name === 'PBKDF2' && kdf.hash === 'SHA-256'
      && Number.isInteger(kdf.iterations) && kdf.iterations >= KDF_MIN_ITERATIONS && kdf.iterations <= KDF_MAX_ITERATIONS
      && typeof kdf.salt === 'string'
      && isPlainObject(cipher) && cipher.name === 'AES-GCM' && cipher.keyLength === 256 && cipher.tagLength === 128
      && typeof cipher.iv === 'string' && typeof raw.ciphertext === 'string';
    if (!valid) throw new VaultError('invalid-envelope');
    if (base64ToBytes(kdf.salt).length < SALT_BYTES) throw new VaultError('invalid-envelope');
    if (base64ToBytes(cipher.iv).length !== IV_BYTES) throw new VaultError('invalid-envelope');
    if (base64ToBytes(raw.ciphertext).length < 17) throw new VaultError('invalid-envelope');

    return {
      format: FORMAT_ID,
      version: FORMAT_VERSION,
      app: 'Arca',
      vaultId: raw.vaultId,
      createdAt: isIsoDate(raw.createdAt) ? raw.createdAt : null,
      updatedAt: isIsoDate(raw.updatedAt) ? raw.updatedAt : null,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt },
      cipher: { name: 'AES-GCM', keyLength: 256, tagLength: 128, iv: cipher.iv },
      ciphertext: raw.ciphertext,
    };
  }

  function serializeEnvelope(envelope) {
    const ordered = {
      format: envelope.format,
      version: envelope.version,
      app: envelope.app,
      vaultId: envelope.vaultId,
      createdAt: envelope.createdAt,
      updatedAt: envelope.updatedAt,
      kdf: envelope.kdf,
      cipher: envelope.cipher,
      ciphertext: envelope.ciphertext,
    };
    return `${JSON.stringify(ordered, null, 2)}\n`;
  }

  /* =========================================================================
   * 4. Validação e saneamento dos dados descriptografados
   * ====================================================================== */

  function cleanString(value, max) {
    return typeof value === 'string' ? value.slice(0, max) : '';
  }

  function cleanDate(value, fallback) {
    return isIsoDate(value) ? new Date(value).toISOString() : fallback;
  }

  function isValidId(value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
  }

  function sanitizeProject(raw, fallbackDate) {
    if (!isPlainObject(raw) || !isValidId(raw.id)) return null;
    const name = cleanString(raw.name, LIMITS.projectName).trim();
    if (!name) return null;
    const createdAt = cleanDate(raw.createdAt, fallbackDate);
    return {
      id: raw.id,
      name,
      description: cleanString(raw.description, LIMITS.projectDesc),
      color: PROJECT_COLOR_IDS.includes(raw.color) ? raw.color : 'slate',
      icon: PROJECT_ICON_IDS.includes(raw.icon) ? raw.icon : 'folder',
      createdAt,
      updatedAt: cleanDate(raw.updatedAt, createdAt),
    };
  }

  function sanitizeItem(raw, projectIds, fallbackDate) {
    if (!isPlainObject(raw) || !isValidId(raw.id)) return null;
    const name = cleanString(raw.name, LIMITS.name).trim();
    if (!name) return null;
    const createdAt = cleanDate(raw.createdAt, fallbackDate);
    const history = Array.isArray(raw.history)
      ? raw.history
        .filter((h) => isPlainObject(h) && typeof h.password === 'string' && h.password)
        .slice(0, HISTORY_LIMIT)
        .map((h) => ({ password: h.password.slice(0, LIMITS.password), changedAt: cleanDate(h.changedAt, createdAt) }))
      : [];
    return {
      id: raw.id,
      name,
      system: cleanString(raw.system, LIMITS.system),
      url: cleanString(raw.url, LIMITS.url),
      username: cleanString(raw.username, LIMITS.username),
      password: cleanString(raw.password, LIMITS.password),
      projectId: projectIds.has(raw.projectId) ? raw.projectId : null,
      category: CATEGORY_MAP.has(raw.category) ? raw.category : 'other',
      notes: cleanString(raw.notes, LIMITS.notes),
      favorite: raw.favorite === true,
      createdAt,
      updatedAt: cleanDate(raw.updatedAt, createdAt),
      lastUsedAt: raw.lastUsedAt ? cleanDate(raw.lastUsedAt, null) : null,
      history,
    };
  }

  function sanitizePayload(raw) {
    if (!isPlainObject(raw) || raw.schema !== SCHEMA_VERSION
      || !Array.isArray(raw.projects) || !Array.isArray(raw.items)) {
      throw new VaultError('invalid-payload');
    }
    const fallbackDate = nowIso();
    const seenProjects = new Set();
    const projects = [];
    for (const entry of raw.projects) {
      const project = sanitizeProject(entry, fallbackDate);
      if (project && !seenProjects.has(project.id)) {
        seenProjects.add(project.id);
        projects.push(project);
      }
    }
    const seenItems = new Set();
    const items = [];
    for (const entry of raw.items) {
      const item = sanitizeItem(entry, seenProjects, fallbackDate);
      if (item && !seenItems.has(item.id)) {
        seenItems.add(item.id);
        items.push(item);
      }
    }
    const vaultName = isPlainObject(raw.vault) ? cleanString(raw.vault.name, LIMITS.vaultName).trim() : '';
    return {
      schema: SCHEMA_VERSION,
      vault: { name: vaultName || 'Meu cofre' },
      projects,
      items,
      dropped: (raw.projects.length - projects.length) + (raw.items.length - items.length),
    };
  }

  function createEmptyVault(name) {
    return { schema: SCHEMA_VERSION, vault: { name }, projects: [], items: [] };
  }

  /* =========================================================================
   * 5. Acesso a arquivos
   * ====================================================================== */

  const FileIO = {
    supportsDirectWrite: typeof window.showOpenFilePicker === 'function' && typeof window.showSaveFilePicker === 'function',
    pickerTypes: [{ description: 'Cofre Arca (.txt)', accept: { 'text/plain': ['.txt'] } }],

    async pickExisting() {
      const [handle] = await window.showOpenFilePicker({
        id: 'arca-vault', types: this.pickerTypes, multiple: false, mode: 'readwrite',
      });
      return handle;
    },

    async pickNew(suggestedName) {
      return window.showSaveFilePicker({ id: 'arca-vault', types: this.pickerTypes, suggestedName });
    },

    async readFile(file) {
      if (file.size > MAX_FILE_BYTES) throw new VaultError('too-large');
      try {
        return { text: await file.text(), name: file.name, size: file.size, lastModified: file.lastModified };
      } catch (error) {
        throw new VaultError('read-failed', error);
      }
    },

    async readHandle(handle) {
      let file;
      try {
        file = await handle.getFile();
      } catch (error) {
        throw new VaultError('read-failed', error);
      }
      return this.readFile(file);
    },

    async hasWritePermission(handle, allowPrompt) {
      if (typeof handle.queryPermission !== 'function') return true;
      const options = { mode: 'readwrite' };
      try {
        if (await handle.queryPermission(options) === 'granted') return true;
        if (!allowPrompt) return false;
        return await handle.requestPermission(options) === 'granted';
      } catch {
        return false;
      }
    },

    /** createWritable grava em um arquivo temporário e só substitui o original no close(). */
    async write(handle, text) {
      let writable = null;
      try {
        writable = await handle.createWritable();
        await writable.write(text);
        await writable.close();
      } catch (error) {
        if (writable) { try { await writable.abort(); } catch { /* já encerrado */ } }
        throw new VaultError('write-failed', error);
      }
    },

    download(fileName, text) {
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName;
      link.rel = 'noopener';
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    },

    pickWithInput() {
      return new Promise((resolve) => {
        const input = $('#file-input');
        input.value = '';
        const cleanup = () => {
          input.removeEventListener('change', onChange);
          input.removeEventListener('cancel', onCancel);
        };
        const onChange = () => { cleanup(); resolve(input.files && input.files[0] ? input.files[0] : null); };
        const onCancel = () => { cleanup(); resolve(null); };
        input.addEventListener('change', onChange);
        input.addEventListener('cancel', onCancel);
        input.click();
      });
    },
  };

  /** Guarda apenas o "handle" do último arquivo (sem conteúdo nem senha) no IndexedDB. */
  const RecentFileStore = {
    open() {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open('arca', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('kv');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    },
    async run(mode, fn) {
      const db = await this.open();
      try {
        return await new Promise((resolve, reject) => {
          const tx = db.transaction('kv', mode);
          const request = fn(tx.objectStore('kv'));
          tx.oncomplete = () => resolve(request ? request.result : undefined);
          tx.onerror = () => reject(tx.error);
        });
      } finally {
        db.close();
      }
    },
    async get() {
      if (!FileIO.supportsDirectWrite || !window.indexedDB) return null;
      try { return (await this.run('readonly', (s) => s.get('last-file'))) || null; } catch { return null; }
    },
    async set(handle) {
      if (!FileIO.supportsDirectWrite || !window.indexedDB || !handle) return;
      try { await this.run('readwrite', (s) => s.put({ handle, name: handle.name, usedAt: Date.now() }, 'last-file')); } catch { /* opcional */ }
    },
    async clear() {
      if (!window.indexedDB) return;
      try { await this.run('readwrite', (s) => s.delete('last-file')); } catch { /* opcional */ }
    },
  };

  /* =========================================================================
   * 6. Gerador de senhas e estimativa de força
   * ====================================================================== */

  const PasswordGenerator = (() => {
    const SETS = {
      upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lower: 'abcdefghijklmnopqrstuvwxyz',
      digits: '0123456789',
      symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~',
    };
    const AMBIGUOUS = new Set('Il1|O0o`\'".,;:'.split(''));

    /** Inteiro uniforme em [0, max) sem viés de módulo (amostragem por rejeição). */
    function randomInt(max) {
      const limit = Math.floor(0x100000000 / max) * max;
      const buffer = new Uint32Array(1);
      do {
        crypto.getRandomValues(buffer);
      } while (buffer[0] >= limit);
      return buffer[0] % max;
    }

    function activeSets(options) {
      return ['upper', 'lower', 'digits', 'symbols']
        .filter((k) => options[k])
        .map((k) => (options.avoidAmbiguous ? [...SETS[k]].filter((c) => !AMBIGUOUS.has(c)).join('') : SETS[k]));
    }

    function poolSize(options) {
      return activeSets(options).reduce((sum, set) => sum + set.length, 0);
    }

    function generate(options) {
      const sets = activeSets(options);
      if (!sets.length) throw new Error('Nenhum conjunto de caracteres selecionado');
      const length = Math.min(128, Math.max(8, Math.trunc(options.length) || 20));
      const pool = sets.join('');
      const chars = sets.map((set) => set[randomInt(set.length)]); // garante 1 de cada conjunto
      while (chars.length < length) chars.push(pool[randomInt(pool.length)]);
      for (let i = chars.length - 1; i > 0; i -= 1) { // Fisher–Yates com fonte segura
        const j = randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
      }
      return chars.join('');
    }

    function entropyBits(options) {
      const size = poolSize(options);
      return size ? Math.round(Math.min(128, Math.max(8, options.length)) * Math.log2(size)) : 0;
    }

    return { generate, entropyBits };
  })();

  const STRENGTH_LABELS = ['Muito fraca', 'Fraca', 'Razoável', 'Forte', 'Muito forte'];
  const COMMON_FRAGMENTS = ['123456', 'password', 'senha', 'qwerty', 'abc123', '111111', 'admin', 'letmein',
    'iloveyou', '000000', '123123', 'welcome', 'dragon', 'monkey', 'brasil', 'mudar', 'teste'];

  function scoreFromBits(bits) {
    if (bits < 28) return 0;
    if (bits < 40) return 1;
    if (bits < 60) return 2;
    if (bits < 80) return 3;
    return 4;
  }

  /** Estimativa aproximada (heurística de entropia com penalidades por padrões comuns). */
  function estimateStrength(password) {
    if (!password) return { score: -1, bits: 0, label: '' };
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/\d/.test(password)) pool += 10;
    if (/[^A-Za-z0-9]/.test(password)) pool += 33;
    const length = [...password].length;
    let bits = length * Math.log2(Math.max(pool, 2));
    const unique = new Set(password).size;
    if (unique <= 2) bits = Math.min(bits, 10);
    else if (unique < length / 3) bits *= 0.6;
    if (/(.)\1{2,}/.test(password)) bits -= 8;
    if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|wert|asdf|zxcv)/i.test(password)) bits -= 10;
    const lower = normalizeText(password);
    if (COMMON_FRAGMENTS.some((f) => lower.includes(f))) bits = Math.min(bits * 0.5, 30);
    bits = Math.max(0, Math.round(bits));
    const score = scoreFromBits(bits);
    return { score, bits, label: STRENGTH_LABELS[score] };
  }

  function strengthMeterHTML(id = '') {
    return `<div class="strength" ${id ? `id="${id}"` : ''} data-score="-1">
      <div class="strength-bar"><span></span><span></span><span></span><span></span></div>
      <span class="strength-label"></span></div>`;
  }

  function updateStrengthMeter(meter, result, emptyLabel = '') {
    if (!meter) return;
    meter.dataset.score = String(result.score);
    const label = meter.querySelector('.strength-label');
    label.textContent = result.score < 0 ? emptyLabel : `${result.label} · ~${result.bits} bits`;
  }

  /* =========================================================================
   * 7. Área de transferência
   * ====================================================================== */

  const Clipboard = (() => {
    let clearTimer = null;

    function legacyCopy(text) {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.setAttribute('aria-hidden', 'true');
      area.className = 'clipboard-buffer';
      document.body.append(area);
      area.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      area.value = '';
      area.remove();
      return ok;
    }

    async function copy(text, { sensitive = false } = {}) {
      let ok = false;
      if (navigator.clipboard && window.isSecureContext) {
        try {
          await navigator.clipboard.writeText(text);
          ok = true;
        } catch {
          ok = false;
        }
      }
      if (!ok) ok = legacyCopy(text);
      if (ok && sensitive && Prefs.get('clearClipboard')) scheduleClear();
      return ok;
    }

    function scheduleClear() {
      clearTimeout(clearTimer);
      clearTimer = setTimeout(async () => {
        if (!navigator.clipboard || !document.hasFocus()) return;
        try { await navigator.clipboard.writeText(''); } catch { /* sem foco/permissão */ }
      }, CLIPBOARD_CLEAR_MS);
    }

    return { copy };
  })();

  /** `doneMessage` descreve o que foi copiado, sem nunca exibir o conteúdo. */
  async function copyWithFeedback(text, doneMessage, sensitive) {
    if (!text) {
      Toast.show('Campo vazio — nada para copiar.', { type: 'info' });
      return false;
    }
    const ok = await Clipboard.copy(text, { sensitive });
    if (ok) {
      const suffix = sensitive && Prefs.get('clearClipboard') ? ' A área de transferência será limpa em 30 s.' : '';
      Toast.show(`${doneMessage}.${suffix}`);
    } else {
      Toast.show('O navegador bloqueou a área de transferência. Revele o campo e copie manualmente.', { type: 'error', duration: 5000 });
    }
    return ok;
  }

  /* =========================================================================
   * 8. Componentes de interface
   * ====================================================================== */

  const ICON_PATHS = {
    logo: '<path d="M12 2.8l7.5 3v5.6c0 4.6-3.1 8.4-7.5 9.8-4.4-1.4-7.5-5.2-7.5-9.8V5.8z"/><circle cx="12" cy="10.4" r="1.9"/><path d="M12 12.3v3.2"/>',
    shield: '<path d="M12 2.8l7.5 3v5.6c0 4.6-3.1 8.4-7.5 9.8-4.4-1.4-7.5-5.2-7.5-9.8V5.8z"/><path d="M8.8 12l2.2 2.2 4.2-4.4"/>',
    lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2"/>',
    eye: '<path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
    eyeOff: '<path d="M3.5 3.5l17 17"/><path d="M10.6 5.6A9.7 9.7 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16.4 16.4 0 0 1-3 3.7M6.6 6.6C3.9 8.3 2.5 12 2.5 12s3.5 6.5 9.5 6.5a9 9 0 0 0 4.4-1.1"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    copy: '<rect x="8.5" y="8.5" width="12" height="12" rx="2.5"/><path d="M15.5 8.5V6A2.5 2.5 0 0 0 13 3.5H6A2.5 2.5 0 0 0 3.5 6v7A2.5 2.5 0 0 0 6 15.5h2.5"/>',
    check: '<path d="M4.5 12.5l5 5 10-11"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    star: '<path d="M12 3.8l2.5 5.1 5.6.8-4 4 .9 5.6L12 16.6l-5 2.7.9-5.6-4-4 5.6-.8z"/>',
    pencil: '<path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12"/><path d="M9 7V4.5h6V7"/>',
    folder: '<path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2.5h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
    briefcase: '<rect x="3.5" y="7.5" width="17" height="12" rx="2"/><path d="M9 7.5v-2A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5v2M3.5 13h17"/>',
    code: '<path d="M8.5 7l-5 5 5 5M15.5 7l5 5-5 5M13.5 4.5l-3 15"/>',
    server: '<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
    globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.5 5.4 3.5 8.5s-1 5.9-3.5 8.5c-2.5-2.6-3.5-5.4-3.5-8.5s1-5.9 3.5-8.5z"/>',
    home: '<path d="M4 10.5L12 4l8 6.5V19a1.5 1.5 0 0 1-1.5 1.5h-4v-6h-5v6h-4A1.5 1.5 0 0 1 4 19z"/>',
    cart: '<path d="M3.5 4.5h2l2.2 10.5h10l2-7.5H6.6"/><circle cx="9" cy="19" r="1.3"/><circle cx="17" cy="19" r="1.3"/>',
    rocket: '<path d="M12.5 15.5l-4-4c1.5-4.5 5-7.5 11-8-.5 6-3.5 9.5-7 12z"/><path d="M8.5 11.5L5 11l2.5-3.5h4M12.5 15.5l.5 3.5 3.5-2.5v-4"/><path d="M6.5 17.5c-1 .5-2 2-2 2s1.5-1 2-2"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8.5-8.5M16 7l2.5 2.5M14 9l2 2"/>',
    bank: '<path d="M3.5 9.5L12 4.5l8.5 5M5.5 10v7M10 10v7M14 10v7M18.5 10v7M3.5 19.5h17"/>',
    mail: '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="M4 7l8 6 8-6"/>',
    users: '<circle cx="9" cy="8.5" r="3.5"/><path d="M2.5 19.5a6.5 6.5 0 0 1 13 0"/><path d="M16 5.2a3.5 3.5 0 0 1 0 6.6M18 14a6.5 6.5 0 0 1 3.5 5.5"/>',
    user: '<circle cx="12" cy="8.5" r="3.8"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
    box: '<path d="M3.5 7.5L12 3.5l8.5 4v9L12 20.5l-8.5-4z"/><path d="M3.5 7.5l8.5 4 8.5-4M12 11.5v9"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    sparkles: '<path d="M11 3.5l1.8 4.7 4.7 1.8-4.7 1.8L11 16.5l-1.8-4.7L4.5 10l4.7-1.8z"/><path d="M18 14.5l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z"/>',
    refresh: '<path d="M20 11.5A8 8 0 0 0 6.3 6.3L4 8.5M4 4v4.5h4.5M4 12.5a8 8 0 0 0 13.7 5.2l2.3-2.2M20 20v-4.5h-4.5"/>',
    save: '<path d="M5.5 3.5h10l5 5v10a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2z"/><path d="M7.5 3.5v5h7v-5M7.5 20.5v-6h9v6"/>',
    download: '<path d="M12 4v11M7 10.5l5 5 5-5M4.5 19.5h15"/>',
    upload: '<path d="M12 15.5v-11M7 9l5-5 5 5M4.5 19.5h15"/>',
    file: '<path d="M6.5 3.5h7L18 8v11a1.5 1.5 0 0 1-1.5 1.5h-10A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1.5-1.5z"/><path d="M13.5 3.5V8H18M8.5 12.5h6M8.5 16h4"/>',
    external: '<path d="M13.5 4.5h6v6M19.5 4.5L11 13"/><path d="M17.5 14v4a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h4"/>',
    chevronRight: '<path d="M9.5 6l6 6-6 6"/>',
    chevronDown: '<path d="M6 9.5l6 6 6-6"/>',
    arrowLeft: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    settings: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    alert: '<path d="M12 4l9 15.5H3z"/><path d="M12 10v4M12 17h.01"/>',
    info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
    layers: '<path d="M12 3.5l8.5 4.5-8.5 4.5L3.5 8z"/><path d="M3.5 12.5L12 17l8.5-4.5M3.5 16.5L12 21l8.5-4.5"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    note: '<path d="M5.5 4.5h13v15h-13z"/><path d="M8.5 9h7M8.5 12.5h7M8.5 16h4"/>',
    history: '<path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.5"/><path d="M4 4v4.5h4.5M12 8v4.5l3 1.5"/>',
    filter: '<path d="M4 5.5h16l-6 7.5v5l-4 1.5v-6.5z"/>',
};

  function icon(name, className = '') {
    const paths = ICON_PATHS[name] || ICON_PATHS.box;
    return `<svg class="i ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${paths}</svg>`;
  }

  function hydrateIcons(root = document) {
    for (const el of $$('[data-icon]', root)) {
      el.innerHTML = icon(el.dataset.icon);
      el.removeAttribute('data-icon');
    }
  }

  /* ---------------- Toasts ---------------- */

  const Toast = {
    show(message, { type = 'success', duration = 2800, action = null } = {}) {
      const region = $('#toast-region');
      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;
      const iconName = type === 'error' ? 'alert' : type === 'info' ? 'info' : 'check';
      toast.innerHTML = `<span class="toast-icon">${icon(iconName)}</span><span class="toast-text"></span>`;
      toast.querySelector('.toast-text').textContent = message;
      if (action) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'toast-action';
        button.textContent = action.label;
        button.addEventListener('click', () => { dismiss(); action.onClick(); }, { once: true });
        toast.append(button);
      }
      region.append(toast);
      while (region.children.length > 3) region.firstElementChild.remove();
      requestAnimationFrame(() => toast.classList.add('is-visible'));
      const dismiss = () => {
        toast.classList.remove('is-visible');
        setTimeout(() => toast.remove(), 250);
      };
      setTimeout(dismiss, action ? Math.max(duration, 6000) : duration);
    },
  };

  /* ---------------- Inert / foco ---------------- */

  function syncInert() {
    const modalOpen = Modal.isOpen();
    const drawerOpen = Drawer.isOpen();
    $('#app').inert = modalOpen || drawerOpen;
    $('#auth').inert = modalOpen;
    $('#drawer-root').inert = modalOpen;
  }

  function focusableIn(root) {
    return $$('a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])', root)
      .filter((el) => el.offsetParent !== null || el === document.activeElement);
  }

  function trapTab(event, container) {
    const items = focusableIn(container);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  /* ---------------- Modal ---------------- */

  const Modal = (() => {
    let current = null;

    function open({ title, body = '', actions = [], dismissValue = null, onMount = null, size = 'sm', tone = '' }) {
      if (current) current.finish(current.dismissValue);
      return new Promise((resolve) => {
        const previousFocus = document.activeElement;
        const layer = document.createElement('div');
        layer.className = 'modal-layer';
        layer.innerHTML = `
          <div class="modal-backdrop" data-modal-dismiss></div>
          <div class="modal modal-${size} ${tone ? `modal-${tone}` : ''}" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-body">
            <h2 class="modal-title" id="modal-title"></h2>
            <div class="modal-body" id="modal-body"></div>
            <div class="modal-actions"></div>
          </div>`;
        $('.modal-title', layer).textContent = title;
        const bodyEl = $('.modal-body', layer);
        if (typeof body === 'string') bodyEl.innerHTML = body;
        else bodyEl.append(body);
        const actionsEl = $('.modal-actions', layer);
        actions.forEach((action, index) => {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = `btn btn-${action.variant || 'secondary'}`;
          button.textContent = action.label;
          button.dataset.modalIndex = String(index);
          if (action.autofocus) button.dataset.autofocus = '';
          actionsEl.append(button);
        });
        hydrateIcons(layer);

        const finish = (value) => {
          if (!current || current.layer !== layer) return;
          current = null;
          layer.classList.remove('is-open');
          setTimeout(() => layer.remove(), 180);
          syncInert();
          if (previousFocus && document.contains(previousFocus)) previousFocus.focus({ preventScroll: true });
          resolve(value);
        };

        layer.addEventListener('click', (event) => {
          if (event.target.closest('[data-modal-dismiss]')) { finish(dismissValue); return; }
          const button = event.target.closest('[data-modal-index]');
          if (!button) return;
          const action = actions[Number(button.dataset.modalIndex)];
          const dialog = $('.modal', layer);
          if (action.validate && !action.validate(dialog)) return;
          finish(action.getValue ? action.getValue(dialog) : action.value);
        });

        current = { layer, finish, dismissValue };
        $('#modal-root').append(layer);
        syncInert();
        if (onMount) onMount($('.modal', layer));
        requestAnimationFrame(() => layer.classList.add('is-open'));
        const target = $('[data-autofocus]', layer) || $('.modal-actions .btn:last-child', layer);
        if (target) target.focus();
      });
    }

    function confirm({ title, message, confirmLabel = 'Confirmar', cancelLabel = 'Cancelar', danger = false }) {
      return open({
        title,
        body: `<p class="modal-text">${esc(message)}</p>`,
        tone: danger ? 'danger' : '',
        dismissValue: false,
        actions: [
          { label: cancelLabel, value: false, variant: 'secondary', autofocus: danger },
          { label: confirmLabel, value: true, variant: danger ? 'danger' : 'primary', autofocus: !danger },
        ],
      });
    }

    function handleKey(event) {
      if (!current) return false;
      if (event.key === 'Escape') {
        event.preventDefault();
        current.finish(current.dismissValue);
        return true;
      }
      if (event.key === 'Tab') trapTab(event, $('.modal', current.layer));
      return true;
    }

    return {
      open,
      confirm,
      handleKey,
      isOpen: () => !!current,
      dismiss: () => { if (current) current.finish(current.dismissValue); },
    };
  })();

  /* ---------------- Drawer lateral ---------------- */

  const Drawer = (() => {
    let current = null;

    function open({ title, subtitle = '', headIcon = '', body, footer = '', isDirty = () => false, onMount = null, kind = '', refId = '' }) {
      const replacing = !!current;
      const previousFocus = replacing ? current.previousFocus : document.activeElement;
      if (replacing) removeLayer(current.layer, true);

      const layer = document.createElement('div');
      layer.className = `drawer-layer${replacing ? ' is-open no-anim' : ''}`;
      layer.innerHTML = `
        <div class="drawer-backdrop" data-drawer-backdrop></div>
        <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
          <header class="drawer-head">
            ${headIcon ? `<div class="drawer-head-icon">${headIcon}</div>` : ''}
            <div class="drawer-head-text">
              <h2 class="drawer-title" id="drawer-title"></h2>
              ${subtitle ? '<p class="drawer-subtitle"></p>' : ''}
            </div>
            <button type="button" class="icon-btn" data-drawer-close aria-label="Fechar painel" title="Fechar (Esc)">${icon('x')}</button>
          </header>
          <div class="drawer-body">${body}</div>
          ${footer ? `<footer class="drawer-foot">${footer}</footer>` : ''}
        </aside>`;
      $('.drawer-title', layer).textContent = title;
      if (subtitle) $('.drawer-subtitle', layer).textContent = subtitle;
      hydrateIcons(layer);

      layer.addEventListener('click', (event) => {
        if (event.target.closest('[data-drawer-close]')) requestClose('button');
        else if (event.target.closest('[data-drawer-backdrop]')) requestClose('backdrop');
      });

      current = { layer, isDirty, previousFocus, kind, refId };
      $('#drawer-root').append(layer);
      document.body.classList.add('has-drawer');
      syncInert();
      if (onMount) onMount($('.drawer', layer));
      if (!replacing) requestAnimationFrame(() => layer.classList.add('is-open'));
      else requestAnimationFrame(() => layer.classList.remove('no-anim'));
      const autofocus = $('[data-autofocus]', layer) || $('[data-drawer-close]', layer);
      autofocus.focus({ preventScroll: true });
      return $('.drawer', layer);
    }

    function wipeFields(layer) {
      for (const field of $$('input, textarea', layer)) field.value = '';
      for (const secret of $$('[data-secret], [data-gen-value]', layer)) secret.textContent = '';
    }

    function removeLayer(layer, immediate) {
      if (immediate) {
        wipeFields(layer);
        layer.remove();
        return;
      }
      layer.classList.remove('is-open');
      setTimeout(() => { wipeFields(layer); layer.remove(); }, 260);
    }

    function close() {
      if (!current) return;
      const { layer, previousFocus } = current;
      current = null;
      removeLayer(layer, false);
      document.body.classList.remove('has-drawer');
      syncInert();
      if (previousFocus && document.contains(previousFocus) && !previousFocus.closest('[inert]')) {
        previousFocus.focus({ preventScroll: true });
      }
    }

    function nudge() {
      if (!current) return;
      const drawer = $('.drawer', current.layer);
      drawer.classList.remove('is-nudged');
      void drawer.offsetWidth;
      drawer.classList.add('is-nudged');
    }

    async function requestClose(source) {
      if (!current) return true;
      if (current.isDirty()) {
        if (source === 'backdrop') {
          nudge();
          Toast.show('Há alterações não salvas. Salve ou use “Cancelar” para descartar.', { type: 'info' });
          return false;
        }
        const discard = await Modal.confirm({
          title: 'Descartar alterações?',
          message: 'As alterações feitas neste formulário serão perdidas.',
          confirmLabel: 'Descartar',
          cancelLabel: 'Continuar editando',
          danger: true,
        });
        if (!discard) return false;
      }
      close();
      return true;
    }

    function handleKey(event) {
      if (!current) return false;
      if (event.key === 'Escape') {
        event.preventDefault();
        requestClose('escape');
        return true;
      }
      if (event.key === 'Tab') trapTab(event, $('.drawer', current.layer));
      return false;
    }

    return {
      open,
      close,
      requestClose,
      handleKey,
      isOpen: () => !!current,
      element: () => (current ? $('.drawer', current.layer) : null),
      info: () => (current ? { kind: current.kind, refId: current.refId } : null),
    };
  })();

  /* ---------------- Helpers de formulário ---------------- */

  function setButtonLoading(button, loading, label) {
    if (!button) return;
    button.disabled = loading;
    button.classList.toggle('is-loading', loading);
    button.setAttribute('aria-busy', String(loading));
    if (label) $('.btn-label', button).textContent = label;
  }

  function setFieldError(input, message) {
    if (!input) return;
    const field = input.closest('.field, .check');
    const errorId = `${input.id}-error`;
    const errorEl = document.getElementById(errorId);
    input.setAttribute('aria-invalid', message ? 'true' : 'false');
    if (field) field.classList.toggle('has-error', !!message);
    if (errorEl) {
      errorEl.textContent = message || '';
      errorEl.hidden = !message;
    }
  }

  function clearFieldErrors(root) {
    for (const input of $$('[aria-invalid="true"]', root)) setFieldError(input, '');
  }

  function showFormAlert(el, message) {
    if (!el) return;
    el.innerHTML = message ? `${icon('alert')}<span></span>` : '';
    if (message) $('span', el).textContent = message;
    el.hidden = !message;
  }

  function togglePasswordVisibility(button) {
    const input = document.getElementById(button.dataset.reveal);
    if (!input) return;
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(reveal));
    button.setAttribute('aria-label', reveal ? 'Ocultar senha' : 'Mostrar senha');
    button.title = reveal ? 'Ocultar senha' : 'Mostrar senha';
    button.innerHTML = icon(reveal ? 'eyeOff' : 'eye');
  }

  function revealButtonHTML(inputId) {
    return `<button type="button" class="icon-btn" data-reveal="${inputId}" aria-label="Mostrar senha" title="Mostrar senha" aria-pressed="false">${icon('eye')}</button>`;
  }

  function formSnapshot(form) {
    const entries = [];
    for (const el of form.elements) {
      if (!el.name) continue;
      if (el.type === 'checkbox' || el.type === 'radio') entries.push([el.name, el.value, el.checked]);
      else entries.push([el.name, el.value]);
    }
    return JSON.stringify(entries);
  }

  /* =========================================================================
   * 9. Estado e sessão
   * ====================================================================== */

  function defaultUiState() {
    return {
      view: 'home',
      query: '',
      filters: { project: 'all', category: 'all', favorites: false, attention: false },
      sort: Prefs.get('sort'),
    };
  }

  const state = {
    session: null,   // { key, vaultId, kdf, createdAt, fileName, handle, mode, lastFileHash, lastEnvelopeText, blocked, lastSavedAt }
    vault: null,     // dados descriptografados (somente em memória)
    dirty: false,
    softDirty: false,
    changeCounter: 0,
    saving: false,
    ui: defaultUiState(),
    auth: { screen: 'welcome', pending: null, failedAttempts: 0 },
  };

  /* ---------------- Tela de acesso ---------------- */

  function showAuthScreen(screen) {
    state.auth.screen = screen;
    $('#app').hidden = true;
    $('#auth').hidden = false;
    for (const id of ['welcome', 'unlock', 'create']) $(`#auth-${id}`).hidden = id !== screen;
    showFormAlert($('#unlock-error'), '');
    showFormAlert($('#create-error'), '');
    clearFieldErrors($('#auth'));
    if (screen === 'welcome') renderRecentFile();
    if (screen === 'unlock') {
      renderUnlockFile();
      $('#unlock-password').focus();
    }
    if (screen === 'create') $('#create-name').focus();
  }

  async function renderRecentFile() {
    const container = $('#auth-recent');
    container.innerHTML = '';
    const recent = await RecentFileStore.get();
    if (!recent || !recent.handle || state.auth.screen !== 'welcome') return;
    container.innerHTML = `
      <button type="button" class="option-tile option-tile-primary" data-action="auth-reopen">
        <span class="option-icon">${icon('history')}</span>
        <span class="option-text"><strong>Continuar com <span class="mono-name"></span></strong>
        <small>Último cofre usado ${esc(relativeTime(recent.usedAt))}</small></span>
        <span class="option-chev">${icon('chevronRight')}</span>
      </button>`;
    $('.mono-name', container).textContent = recent.name;
  }

  function renderUnlockFile() {
    const pending = state.auth.pending;
    const chip = $('#unlock-file');
    if (!pending) return;
    const meta = [];
    if (pending.size) meta.push(formatBytes(pending.size));
    if (pending.envelope && pending.envelope.updatedAt) meta.push(`salvo ${relativeTime(pending.envelope.updatedAt)}`);
    meta.push(pending.handle && FileIO.supportsDirectWrite ? 'gravação direta' : 'modo exportação');
    chip.innerHTML = `<span class="file-chip-icon">${icon('file')}</span>
      <span class="file-chip-text"><strong></strong><small></small></span>
      <button type="button" class="btn-link" data-action="auth-open">Trocar</button>`;
    $('strong', chip).textContent = pending.fileName;
    $('small', chip).textContent = meta.join(' · ');
    const iterations = pending.envelope ? pending.envelope.kdf.iterations : KDF_DEFAULT_ITERATIONS;
    $('#unlock-kdf').innerHTML = `${icon('shield')} Chave derivada localmente com PBKDF2-SHA-256 · ${iterations.toLocaleString('pt-BR')} iterações`;
  }

  /** Lê e valida um arquivo escolhido; em caso de sucesso, mostra a tela de desbloqueio. */
  async function loadPendingFile({ handle = null, file = null }) {
    try {
      const result = handle ? await FileIO.readHandle(handle) : await FileIO.readFile(file);
      const envelope = parseEnvelope(result.text);
      state.auth.pending = {
        handle: FileIO.supportsDirectWrite ? handle : null,
        fileName: result.name,
        size: result.size,
        envelope,
      };
      state.auth.failedAttempts = 0;
      showAuthScreen('unlock');
    } catch (error) {
      reportError('abrir arquivo', error);
      Toast.show(errorMessage(error, 'Não foi possível abrir o arquivo.'), { type: 'error', duration: 5000 });
    }
  }

  async function chooseExistingFile() {
    if (FileIO.supportsDirectWrite) {
      try {
        const handle = await FileIO.pickExisting();
        await loadPendingFile({ handle });
      } catch (error) {
        if (!isAbortError(error)) {
          reportError('seletor de arquivo', error);
          Toast.show('Não foi possível abrir o seletor de arquivos.', { type: 'error' });
        }
      }
      return;
    }
    const file = await FileIO.pickWithInput();
    if (file) await loadPendingFile({ file });
  }

  async function reopenRecentFile() {
    const recent = await RecentFileStore.get();
    if (!recent || !recent.handle) return;
    const granted = await FileIO.hasWritePermission(recent.handle, true);
    if (!granted) {
      try {
        const readState = await recent.handle.requestPermission({ mode: 'read' });
        if (readState !== 'granted') throw new Error('denied');
      } catch {
        Toast.show('Permissão negada para acessar o arquivo. Use “Abrir cofre existente”.', { type: 'error' });
        return;
      }
    }
    await loadPendingFile({ handle: recent.handle });
  }

  async function handleUnlockSubmit(event) {
    event.preventDefault();
    const pending = state.auth.pending;
    const input = $('#unlock-password');
    const button = $('#unlock-submit');
    showFormAlert($('#unlock-error'), '');
    if (!pending) { showAuthScreen('welcome'); return; }
    if (!input.value) {
      showFormAlert($('#unlock-error'), 'Digite a senha mestra.');
      input.focus();
      return;
    }
    setButtonLoading(button, true, 'Desbloqueando…');
    try {
      if (state.auth.failedAttempts >= 3) {
        await sleep(Math.min(1000 * 2 ** (state.auth.failedAttempts - 3), 15000));
      }
      let text = null;
      let envelope = pending.envelope;
      if (pending.handle) {
        text = (await FileIO.readHandle(pending.handle)).text; // relê para pegar a versão mais recente
        envelope = parseEnvelope(text);
      }
      const key = await VaultCrypto.deriveKey(input.value, base64ToBytes(envelope.kdf.salt), envelope.kdf.iterations);
      const vault = sanitizePayload(await VaultCrypto.open(key, envelope));
      const envelopeText = text || serializeEnvelope(envelope);
      input.value = '';
      state.session = {
        key,
        vaultId: envelope.vaultId,
        kdf: { iterations: envelope.kdf.iterations, salt: envelope.kdf.salt },
        createdAt: envelope.createdAt || nowIso(),
        fileName: pending.fileName,
        handle: pending.handle,
        mode: pending.handle ? 'fsa' : 'manual',
        lastFileHash: text ? await VaultCrypto.sha256Hex(text) : null,
        lastEnvelopeText: envelopeText,
        lastSavedAt: envelope.updatedAt ? Date.parse(envelope.updatedAt) : null,
        blocked: null,
      };
      const { dropped } = vault;
      delete vault.dropped;
      state.vault = vault;
      state.auth.failedAttempts = 0;
      if (pending.handle) RecentFileStore.set(pending.handle);
      enterApp();
      Toast.show(`Cofre “${vault.vault.name}” desbloqueado.`);
      if (dropped > 0) {
        Toast.show(`${plural(dropped, 'registro inválido foi ignorado', 'registros inválidos foram ignorados')}. O arquivo original não foi alterado.`, { type: 'info', duration: 6000 });
      }
    } catch (error) {
      if (!(error instanceof VaultError) || error.code !== 'decrypt-failed') reportError('desbloqueio', error);
      if (error instanceof VaultError && error.code === 'decrypt-failed') state.auth.failedAttempts += 1;
      showFormAlert($('#unlock-error'), errorMessage(error, 'Não foi possível desbloquear o cofre.'));
      const card = $('.auth-card');
      card.classList.remove('shake');
      void card.offsetWidth;
      card.classList.add('shake');
      input.select();
    } finally {
      setButtonLoading(button, false, 'Desbloquear');
    }
  }

  function validateCreateForm() {
    const name = $('#create-name');
    const password = $('#create-password');
    const confirm = $('#create-confirm');
    const ack = $('#create-ack');
    clearFieldErrors($('#auth-create'));
    const errors = [];
    if (!name.value.trim()) errors.push([name, 'Informe um nome para o cofre.']);
    const strength = estimateStrength(password.value);
    if (!password.value) errors.push([password, 'Defina a senha mestra.']);
    else if ([...password.value].length < MIN_MASTER_LENGTH) errors.push([password, `A senha mestra deve ter pelo menos ${MIN_MASTER_LENGTH} caracteres.`]);
    else if (strength.score < 2) errors.push([password, 'Senha mestra muito previsível. Use uma frase mais longa ou mais variada.']);
    if (!confirm.value) errors.push([confirm, 'Confirme a senha mestra.']);
    else if (confirm.value !== password.value) errors.push([confirm, 'As senhas não coincidem.']);
    if (!ack.checked) errors.push([ack, 'Confirme que entendeu que a senha não pode ser recuperada.']);
    for (const [input, message] of errors) setFieldError(input, message);
    if (errors.length) errors[0][0].focus();
    return errors.length === 0;
  }

  async function handleCreateSubmit(event) {
    event.preventDefault();
    showFormAlert($('#create-error'), '');
    if (!validateCreateForm()) return;
    const name = $('#create-name').value.trim().slice(0, LIMITS.vaultName);
    const iterations = Number($('#create-iterations').value) || KDF_DEFAULT_ITERATIONS;
    const button = $('#create-submit');
    let handle = null;
    let fileName = `${slugify(name)}.txt`;

    // O seletor precisa ser aberto antes de operações demoradas (exige gesto do usuário).
    if (FileIO.supportsDirectWrite) {
      try {
        handle = await FileIO.pickNew(fileName);
      } catch (error) {
        if (!isAbortError(error)) {
          reportError('criar arquivo', error);
          showFormAlert($('#create-error'), 'Não foi possível escolher o local do arquivo.');
        }
        return;
      }
      const existing = await handle.getFile().catch(() => null);
      if (existing && existing.size > 0) {
        const overwrite = await Modal.confirm({
          title: 'Substituir arquivo existente?',
          message: `“${handle.name}” já possui conteúdo (${formatBytes(existing.size)}). Ao continuar, ele será substituído pelo novo cofre vazio. Esta ação não pode ser desfeita.`,
          confirmLabel: 'Substituir arquivo',
          cancelLabel: 'Cancelar',
          danger: true,
        });
        if (!overwrite) return;
      }
      fileName = handle.name;
    }

    setButtonLoading(button, true, 'Criando cofre…');
    try {
      const salt = VaultCrypto.randomBytes(SALT_BYTES);
      const key = await VaultCrypto.deriveKey($('#create-password').value, salt, iterations);
      const createdAt = nowIso();
      state.session = {
        key,
        vaultId: newId(),
        kdf: { iterations, salt: bytesToBase64(salt) },
        createdAt,
        fileName,
        handle,
        mode: handle ? 'fsa' : 'manual',
        lastFileHash: null,
        lastEnvelopeText: null,
        lastSavedAt: null,
        blocked: null,
      };
      state.vault = createEmptyVault(name);
      const text = await sealCurrentVault();
      if (handle) {
        await FileIO.write(handle, text);
        state.session.lastFileHash = await VaultCrypto.sha256Hex(text);
        RecentFileStore.set(handle);
      } else {
        FileIO.download(fileName, text);
      }
      state.session.lastEnvelopeText = text;
      state.session.lastSavedAt = Date.now();
      $('#create-password').value = '';
      $('#create-confirm').value = '';
      $('#create-ack').checked = false;
      updateStrengthMeter($('#create-strength'), { score: -1 }, `Mínimo de ${MIN_MASTER_LENGTH} caracteres`);
      enterApp();
      Toast.show(handle
        ? `Cofre criado e salvo em “${fileName}”.`
        : `Cofre criado. O arquivo “${fileName}” foi baixado — guarde-o em local seguro.`, { duration: 4500 });
    } catch (error) {
      reportError('criar cofre', error);
      if (state.session) state.session.key = null;
      state.session = null;
      state.vault = null;
      showFormAlert($('#create-error'), errorMessage(error, 'Não foi possível criar o cofre.'));
    } finally {
      setButtonLoading(button, false, 'Criar cofre e escolher arquivo');
    }
  }

  /* ---------------- Gravação ---------------- */

  function envelopeHeader() {
    const s = state.session;
    return {
      format: FORMAT_ID,
      version: FORMAT_VERSION,
      app: 'Arca',
      vaultId: s.vaultId,
      createdAt: s.createdAt,
      updatedAt: nowIso(),
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: s.kdf.iterations, salt: s.kdf.salt },
    };
  }

  function buildPayload() {
    const v = state.vault;
    return { schema: SCHEMA_VERSION, vault: { name: v.vault.name }, projects: v.projects, items: v.items };
  }

  async function sealCurrentVault() {
    const envelope = await VaultCrypto.seal(state.session.key, envelopeHeader(), buildPayload());
    return serializeEnvelope(envelope);
  }

  function markDirty() {
    state.dirty = true;
    state.changeCounter += 1;
    renderSaveStatus();
    scheduleAutosave();
  }

  /** Aplica uma alteração aos dados do cofre e atualiza a interface. */
  function commit(mutator, { soft = false } = {}) {
    if (!state.vault) return false;
    mutator(state.vault);
    if (soft) {
      state.softDirty = true;
      scheduleAutosave();
    } else {
      markDirty();
    }
    renderApp();
    return true;
  }

  let autosaveTimer = null;

  function canAutosave() {
    const s = state.session;
    return !!(s && s.mode === 'fsa' && s.handle && Prefs.get('autosave') && !s.blocked);
  }

  function scheduleAutosave() {
    clearTimeout(autosaveTimer);
    if (!canAutosave()) return;
    autosaveTimer = setTimeout(() => saveVault({ interactive: false }), AUTOSAVE_DELAY_MS);
  }

  let saveQueue = Promise.resolve(true);
  function saveVault(options) {
    const run = saveQueue.then(() => performSave(options), () => performSave(options));
    saveQueue = run.catch(() => false);
    return run;
  }

  async function detectExternalChange(session) {
    if (!session.lastFileHash) return false;
    try {
      const { text } = await FileIO.readHandle(session.handle);
      return (await VaultCrypto.sha256Hex(text)) !== session.lastFileHash;
    } catch {
      return true; // arquivo removido ou ilegível: tratar como conflito
    }
  }

  async function performSave({ interactive = false } = {}) {
    const session = state.session;
    if (!session || !state.vault) return false;
    if (!interactive && !state.dirty && !state.softDirty) return true;
    const generation = state.changeCounter;
    state.saving = true;
    renderSaveStatus();
    try {
      const text = await sealCurrentVault();
      if (session.mode === 'fsa' && session.handle) {
        const permitted = await FileIO.hasWritePermission(session.handle, interactive);
        if (!permitted) {
          session.blocked = 'permission';
          if (interactive) return await offerAlternativeSave('Sem permissão para gravar', 'O navegador não permitiu gravar no arquivo do cofre. Você pode salvar em um novo arquivo ou exportar uma cópia.');
          return false;
        }
        if (await detectExternalChange(session)) {
          if (!interactive) {
            session.blocked = 'conflict';
            Toast.show('O arquivo do cofre foi alterado fora do Arca. O salvamento automático foi pausado.', { type: 'error', duration: 6000 });
            return false;
          }
          const choice = await askConflictResolution();
          if (choice === 'save-as') return await saveAsNewFile();
          if (choice !== 'overwrite') return false;
        }
        await FileIO.write(session.handle, text);
        session.lastFileHash = await VaultCrypto.sha256Hex(text);
      } else {
        FileIO.download(session.fileName, text);
        Toast.show(`Arquivo “${session.fileName}” exportado. Substitua a cópia anterior por ele.`, { type: 'info', duration: 5000 });
      }
      session.lastEnvelopeText = text;
      session.lastSavedAt = Date.now();
      session.blocked = null;
      if (state.changeCounter === generation) {
        state.dirty = false;
        state.softDirty = false;
      }
      if (interactive && session.mode === 'fsa') Toast.show('Cofre salvo.');
      return true;
    } catch (error) {
      reportError('salvar', error);
      if (state.session) state.session.blocked = 'error';
      Toast.show(errorMessage(error, 'Falha ao salvar o cofre.'), { type: 'error', duration: 6000 });
      return false;
    } finally {
      state.saving = false;
      renderSaveStatus();
    }
  }

  function askConflictResolution() {
    return Modal.open({
      title: 'O arquivo foi alterado fora do Arca',
      body: `<p class="modal-text">O conteúdo do arquivo <strong>${esc(state.session.fileName)}</strong> não corresponde à última versão salva por esta sessão. Ele pode ter sido editado, restaurado de backup ou removido.</p>
        <p class="modal-text muted">Sobrescrever substituirá o conteúdo atual do arquivo pelos dados abertos aqui.</p>`,
      tone: 'danger',
      dismissValue: 'cancel',
      size: 'md',
      actions: [
        { label: 'Cancelar', value: 'cancel', autofocus: true },
        { label: 'Salvar como novo arquivo', value: 'save-as' },
        { label: 'Sobrescrever', value: 'overwrite', variant: 'danger' },
      ],
    });
  }

  async function offerAlternativeSave(title, message) {
    const actions = [{ label: 'Cancelar', value: 'cancel' }, { label: 'Exportar cópia', value: 'export' }];
    if (FileIO.supportsDirectWrite) actions.push({ label: 'Salvar como…', value: 'save-as', variant: 'primary', autofocus: true });
    const choice = await Modal.open({ title, body: `<p class="modal-text">${esc(message)}</p>`, actions, dismissValue: 'cancel', size: 'md' });
    if (choice === 'save-as') return saveAsNewFile();
    if (choice === 'export') return exportBackup();
    return false;
  }

  async function saveAsNewFile() {
    const session = state.session;
    if (!session || !FileIO.supportsDirectWrite) return false;
    let handle;
    try {
      handle = await FileIO.pickNew(session.fileName);
    } catch (error) {
      if (!isAbortError(error)) Toast.show('Não foi possível abrir o seletor de arquivos.', { type: 'error' });
      return false;
    }
    try {
      const existing = await handle.getFile().catch(() => null);
      const isSameFile = session.handle && typeof handle.isSameEntry === 'function' && await handle.isSameEntry(session.handle);
      if (existing && existing.size > 0 && !isSameFile) {
        const ok = await Modal.confirm({
          title: 'Substituir arquivo existente?',
          message: `“${handle.name}” já possui conteúdo (${formatBytes(existing.size)}). Ele será substituído pelo cofre atual.`,
          confirmLabel: 'Substituir', danger: true,
        });
        if (!ok) return false;
      }
      const text = await sealCurrentVault();
      await FileIO.write(handle, text);
      Object.assign(session, {
        handle, fileName: handle.name, mode: 'fsa', blocked: null,
        lastFileHash: await VaultCrypto.sha256Hex(text), lastEnvelopeText: text, lastSavedAt: Date.now(),
      });
      state.dirty = false;
      state.softDirty = false;
      RecentFileStore.set(handle);
      renderApp();
      Toast.show(`Cofre salvo em “${handle.name}”.`);
      return true;
    } catch (error) {
      reportError('salvar como', error);
      Toast.show(errorMessage(error, 'Falha ao salvar o arquivo.'), { type: 'error' });
      return false;
    }
  }

  async function exportBackup() {
    if (!state.session) return false;
    try {
      const text = await sealCurrentVault();
      const base = state.session.fileName.replace(/\.txt$/i, '');
      FileIO.download(`${base}-backup-${timestampForFile()}.txt`, text);
      Toast.show('Cópia de backup criptografada exportada.');
      return true;
    } catch (error) {
      reportError('exportar', error);
      Toast.show(errorMessage(error, 'Falha ao exportar o backup.'), { type: 'error' });
      return false;
    }
  }

  /* ---------------- Bloqueio ---------------- */

  async function lockVault({ reason = 'manual' } = {}) {
    if (!state.session) return;
    if (state.dirty) {
      if (reason === 'idle') {
        if (!canAutosave() || !(await saveVault({ interactive: false }))) return; // não perde dados
      } else {
        const choice = await Modal.open({
          title: 'Há alterações não salvas',
          body: '<p class="modal-text">Se você bloquear agora sem salvar, as alterações feitas desde o último salvamento serão perdidas.</p>',
          size: 'md',
          dismissValue: 'cancel',
          actions: [
            { label: 'Cancelar', value: 'cancel' },
            { label: 'Bloquear sem salvar', value: 'discard', variant: 'danger-ghost' },
            { label: 'Salvar e bloquear', value: 'save', variant: 'primary', autofocus: true },
          ],
        });
        if (choice === 'cancel' || !choice) return;
        if (choice === 'save' && !(await saveVault({ interactive: true }))) return;
      }
    } else if (state.softDirty && canAutosave()) {
      await saveVault({ interactive: false });
    }

    const session = state.session;
    if (!session) return;
    let envelope = null;
    try { envelope = session.lastEnvelopeText ? parseEnvelope(session.lastEnvelopeText) : null; } catch { envelope = null; }
    state.auth.pending = envelope ? {
      handle: session.handle, fileName: session.fileName, size: session.lastEnvelopeText.length, envelope,
    } : null;
    wipeSession();
    showAuthScreen(state.auth.pending ? 'unlock' : 'welcome');
    Toast.show(reason === 'idle' ? 'Cofre bloqueado por inatividade.' : 'Cofre bloqueado.', { type: 'info' });
  }

  /** Remove referências à chave e aos dados descriptografados e limpa a interface. */
  function wipeSession() {
    clearTimeout(autosaveTimer);
    Modal.dismiss();
    Drawer.close();
    if (state.session) {
      state.session.key = null;
      state.session.lastEnvelopeText = null;
    }
    if (state.vault) {
      for (const item of state.vault.items) { item.password = ''; item.history = []; }
    }
    state.session = null;
    state.vault = null;
    state.dirty = false;
    state.softDirty = false;
    state.ui = defaultUiState();
    $('#view').innerHTML = '';
    $('#nav-projects').innerHTML = '';
    $('#nav-categories').innerHTML = '';
    $('#vault-card').innerHTML = '';
    $('#global-search').value = '';
    for (const input of $$('#auth input[type="password"]')) input.value = '';
    closeSidebar();
  }

  /* ---------------- Bloqueio por inatividade ---------------- */

  const IdleLock = (() => {
    let lastActivity = Date.now();
    let timer = null;
    const bump = () => { lastActivity = Date.now(); };

    function start() {
      stop();
      lastActivity = Date.now();
      timer = setInterval(() => {
        const minutes = Prefs.get('autoLockMinutes');
        if (!state.session || !minutes) return;
        if (Date.now() - lastActivity >= minutes * 60000) lockVault({ reason: 'idle' });
      }, 15000);
    }

    function stop() {
      clearInterval(timer);
      timer = null;
    }

    for (const evt of ['pointerdown', 'keydown', 'wheel', 'touchstart', 'mousemove']) {
      window.addEventListener(evt, bump, { passive: true });
    }
    return { start, stop };
  })();

  function enterApp() {
    state.ui = defaultUiState();
    $('#auth').hidden = true;
    $('#app').hidden = false;
    renderApp();
    IdleLock.start();
    $('#view').focus({ preventScroll: true });
  }

  /* =========================================================================
   * 10. Renderização
   * ====================================================================== */

  function findItem(id) {
    return state.vault ? state.vault.items.find((i) => i.id === id) || null : null;
  }

  function findProject(id) {
    return state.vault ? state.vault.projects.find((p) => p.id === id) || null : null;
  }

  function projectCounts() {
    const counts = new Map();
    for (const item of state.vault.items) {
      const key = item.projectId || 'none';
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    return counts;
  }

  function sortedProjects() {
    return [...state.vault.projects].sort((a, b) => a.name.localeCompare(b.name, 'pt-BR', { sensitivity: 'base' }));
  }

  /** Análise de saúde calculada somente em memória (nunca persistida). */
  function passwordHealth() {
    const counts = new Map();
    for (const item of state.vault.items) {
      if (item.password) counts.set(item.password, (counts.get(item.password) || 0) + 1);
    }
    const flagged = new Map();
    for (const item of state.vault.items) {
      const reasons = [];
      if (item.password && estimateStrength(item.password).score < 2) reasons.push('fraca');
      if (item.password && counts.get(item.password) > 1) reasons.push('reutilizada');
      if (reasons.length) flagged.set(item.id, reasons);
    }
    return flagged;
  }

  function avatarHTML(item, size = '') {
    const category = CATEGORY_MAP.get(item.category) || CATEGORY_MAP.get('other');
    const source = (item.system || item.name || '?').trim();
    const letter = (source.match(/[\p{L}\p{N}]/u) || ['?'])[0].toUpperCase();
    return `<span class="avatar pc-${category.color} ${size ? `avatar-${size}` : ''}" aria-hidden="true">${esc(letter)}</span>`;
  }

  function projectChipHTML(project, { clickable = false } = {}) {
    if (!project) return '<span class="chip chip-muted">Sem projeto</span>';
    const inner = `<span class="chip-dot pc-${project.color}"></span><span class="chip-text">${esc(project.name)}</span>`;
    return clickable
      ? `<button type="button" class="chip chip-button" data-action="open-project" data-id="${esc(project.id)}">${inner}</button>`
      : `<span class="chip">${inner}</span>`;
  }

  function renderApp() {
    if (!state.vault) return;
    renderSidebar();
    renderView();
    renderSaveStatus();
  }

  function renderVaultCard() {
    const s = state.session;
    const modeLabel = s.mode === 'fsa' ? 'Gravação direta' : 'Exportação manual';
    $('#vault-card').innerHTML = `
      <span class="vault-card-icon">${icon('lock')}</span>
      <span class="vault-card-text">
        <span class="vault-card-name"></span>
        <span class="vault-card-file" title=""></span>
      </span>
      <span class="badge ${s.mode === 'fsa' ? 'badge-accent' : 'badge-warn'}" title="${s.mode === 'fsa' ? 'As alterações são gravadas diretamente no arquivo' : 'Salvar gera um novo arquivo para download'}">${modeLabel}</span>`;
    $('.vault-card-name', $('#vault-card')).textContent = state.vault.vault.name;
    const fileEl = $('.vault-card-file', $('#vault-card'));
    fileEl.textContent = s.fileName;
    fileEl.title = s.fileName;
  }

  function navCountHTML(n) {
    return n ? `<span class="nav-count">${n}</span>` : '';
  }

  function renderSidebar() {
    const { items } = state.vault;
    const counts = projectCounts();
    const ui = state.ui;
    renderVaultCard();
    $('#count-all').textContent = items.length || '';
    $('#count-favorites').textContent = items.filter((i) => i.favorite).length || '';

    const onlyFilter = (key, value) => ui.view === 'items' && !ui.query && activeFilterKeys().length === 1 && ui.filters[key] === value;

    for (const button of $$('.nav [data-nav]')) {
      const nav = button.dataset.nav;
      const active = (nav === 'home' && ui.view === 'home')
        || (nav === 'all' && ui.view === 'items' && !ui.query && activeFilterKeys().length === 0)
        || (nav === 'favorites' && onlyFilter('favorites', true));
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }

    const projects = sortedProjects();
    const projectRows = projects.map((p) => `
      <button type="button" class="nav-item nav-item-sub" data-action="open-project" data-id="${esc(p.id)}" ${onlyFilter('project', p.id) ? 'aria-current="page"' : ''}>
        <span class="nav-dot pc-${p.color}"></span><span class="nav-label">${esc(p.name)}</span>${navCountHTML(counts.get(p.id) || 0)}
      </button>`).join('');
    const unassigned = counts.get('none') || 0;
    const unassignedRow = unassigned ? `
      <button type="button" class="nav-item nav-item-sub" data-action="open-project" data-id="none" ${onlyFilter('project', 'none') ? 'aria-current="page"' : ''}>
        <span class="nav-dot nav-dot-empty"></span><span class="nav-label">Sem projeto</span>${navCountHTML(unassigned)}
      </button>` : '';
    $('#nav-projects').innerHTML = projectRows + unassignedRow
      || '<button type="button" class="nav-empty" data-action="new-project">+ Criar primeiro projeto</button>';

    const categoryCounts = new Map();
    for (const item of items) categoryCounts.set(item.category, (categoryCounts.get(item.category) || 0) + 1);
    $('#nav-categories').innerHTML = CATEGORIES.map((c) => `
      <button type="button" class="nav-item nav-item-sub" data-action="open-category" data-id="${c.id}" ${onlyFilter('category', c.id) ? 'aria-current="page"' : ''}>
        <span class="nav-cat-icon">${icon(c.icon)}</span><span class="nav-label">${esc(c.label)}</span>${navCountHTML(categoryCounts.get(c.id) || 0)}
      </button>`).join('');
  }

  function renderSaveStatus() {
    const el = $('#save-status');
    const s = state.session;
    if (!el || !s) return;
    let tone = 'ok';
    let label = 'Salvo';
    let title = 'Todas as alterações foram gravadas';
    let iconName = 'check';
    if (state.saving) {
      tone = 'busy'; label = 'Salvando…'; iconName = 'refresh'; title = 'Gravando o arquivo do cofre';
    } else if (s.blocked === 'conflict') {
      tone = 'error'; label = 'Conflito'; iconName = 'alert'; title = 'O arquivo mudou fora do Arca. Clique para resolver.';
    } else if (s.blocked === 'permission') {
      tone = 'error'; label = 'Sem permissão'; iconName = 'alert'; title = 'Clique para autorizar a gravação no arquivo';
    } else if (s.blocked === 'error' && state.dirty) {
      tone = 'error'; label = 'Falha ao salvar'; iconName = 'alert'; title = 'Clique para tentar novamente';
    } else if (state.dirty) {
      tone = 'dirty';
      label = s.mode === 'fsa' ? 'Não salvo' : 'Exportar alterações';
      iconName = s.mode === 'fsa' ? 'save' : 'download';
      title = s.mode === 'fsa' ? 'Há alterações não salvas. Clique ou use Ctrl+S.' : 'Há alterações não salvas. Clique para baixar o arquivo atualizado (Ctrl+S).';
    } else if (s.lastSavedAt) {
      title = `Salvo ${relativeTime(s.lastSavedAt)}`;
    }
    el.dataset.tone = tone;
    el.title = title;
    el.setAttribute('aria-label', `${label}. ${title}`);
    el.innerHTML = `${icon(iconName)}<span class="save-status-label">${esc(label)}</span>`;
  }

  /* ---------------- Filtros, pesquisa e ordenação ---------------- */

  function activeFilterKeys() {
    const f = state.ui.filters;
    const keys = [];
    if (f.project !== 'all') keys.push('project');
    if (f.category !== 'all') keys.push('category');
    if (f.favorites) keys.push('favorites');
    if (f.attention) keys.push('attention');
    return keys;
  }

  function searchHaystack(item, projectsById) {
    const project = projectsById.get(item.projectId);
    const category = CATEGORY_MAP.get(item.category);
    const url = toSafeUrl(item.url);
    // Senhas e observações NÃO entram na pesquisa.
    return normalizeText([
      item.name, item.system, item.username, url ? url.host : item.url,
      project ? project.name : 'sem projeto', category ? category.label : '',
    ].join(' \u0001 '));
  }

  function filteredItems() {
    const { filters, query, sort } = state.ui;
    const projectsById = new Map(state.vault.projects.map((p) => [p.id, p]));
    const tokens = normalizeText(query).split(/\s+/).filter(Boolean);
    const health = filters.attention ? passwordHealth() : null;
    const list = state.vault.items.filter((item) => {
      if (filters.project === 'none' && item.projectId) return false;
      if (filters.project !== 'all' && filters.project !== 'none' && item.projectId !== filters.project) return false;
      if (filters.category !== 'all' && item.category !== filters.category) return false;
      if (filters.favorites && !item.favorite) return false;
      if (health && !health.has(item.id)) return false;
      if (tokens.length) {
        const hay = searchHaystack(item, projectsById);
        if (!tokens.every((t) => hay.includes(t))) return false;
      }
      return true;
    });
    const byName = (a, b) => a.name.localeCompare(b.name, 'pt-BR', { sensitivity: 'base', numeric: true });
    const byUpdated = (a, b) => Date.parse(a.updatedAt) - Date.parse(b.updatedAt);
    const comparators = {
      'name-asc': byName,
      'name-desc': (a, b) => byName(b, a),
      'updated-desc': (a, b) => byUpdated(b, a),
      'updated-asc': byUpdated,
    };
    return list.sort(comparators[sort] || byName);
  }

  function navigate(next, { focus = true } = {}) {
    const ui = state.ui;
    if (next.view) ui.view = next.view;
    if (next.filters) ui.filters = { project: 'all', category: 'all', favorites: false, attention: false, ...next.filters };
    if (next.clearQuery) {
      ui.query = '';
      $('#global-search').value = '';
    }
    closeSidebar();
    renderApp();
    $('#view').scrollTop = 0;
    window.scrollTo({ top: 0 });
    if (focus) {
      const heading = $('#view h1');
      if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus({ preventScroll: true }); }
    }
  }

  /* ---------------- Visão geral ---------------- */

  function renderView() {
    const view = $('#view');
    view.innerHTML = state.ui.view === 'home' ? homeViewHTML() : itemsViewHTML();
  }

  function statTileHTML({ label, value, iconName, action, nav, tone = '', hint = '' }) {
    return `<button type="button" class="stat ${tone ? `stat-${tone}` : ''}" data-action="${action}" ${nav ? `data-nav="${nav}"` : ''}>
      <span class="stat-icon">${icon(iconName)}</span>
      <span class="stat-value">${value.toLocaleString('pt-BR')}</span>
      <span class="stat-label">${esc(label)}</span>
      ${hint ? `<span class="stat-hint">${esc(hint)}</span>` : ''}
    </button>`;
  }

  function emptyVaultHTML() {
    return `<section class="empty-hero">
      <div class="empty-hero-art" aria-hidden="true">${icon('logo')}</div>
      <h2>Seu cofre está pronto — e vazio</h2>
      <p>Adicione a primeira credencial ou crie projetos para organizar acessos por cliente, sistema ou equipe.</p>
      <div class="empty-actions">
        <button type="button" class="btn btn-primary" data-action="new-item">${icon('plus')}Adicionar credencial</button>
        <button type="button" class="btn btn-secondary" data-action="new-project">${icon('folder')}Criar projeto</button>
        <button type="button" class="btn btn-ghost" data-action="open-generator">${icon('sparkles')}Gerar senha</button>
      </div>
    </section>`;
  }

  function projectCardHTML(project, count) {
    const isNone = !project;
    const id = isNone ? 'none' : project.id;
    const color = isNone ? 'slate' : project.color;
    const name = isNone ? 'Sem projeto' : project.name;
    const description = isNone ? 'Credenciais ainda não organizadas' : (project.description || 'Sem descrição');
    return `<button type="button" class="project-card" data-action="open-project" data-id="${esc(id)}">
      <span class="project-card-top">
        <span class="project-icon pc-${color}">${icon(isNone ? 'box' : project.icon)}</span>
        <span class="project-count">${count}</span>
      </span>
      <span class="project-name">${esc(name)}</span>
      <span class="project-desc">${esc(description)}</span>
      <span class="project-foot">${plural(count, 'credencial', 'credenciais')}${isNone ? '' : ` · criado ${esc(relativeTime(project.createdAt))}`}</span>
    </button>`;
  }

  function compactRowHTML(item, projectsById, meta) {
    const project = projectsById.get(item.projectId);
    const sub = item.username || item.system || displayUrl(toSafeUrl(item.url)) || 'Sem usuário';
    return `<li class="compact-row">
      <button type="button" class="compact-main" data-action="view-item" data-id="${esc(item.id)}">
        ${avatarHTML(item)}
        <span class="row-text"><span class="row-title">${esc(item.name)}</span><span class="row-sub">${esc(sub)}</span></span>
      </button>
      <span class="compact-meta">${meta || projectChipHTML(project)}</span>
      <span class="row-actions">
        <button type="button" class="icon-btn icon-btn-sm" data-action="copy-user" data-id="${esc(item.id)}" ${item.username ? '' : 'disabled'} aria-label="Copiar usuário de ${esc(item.name)}" title="Copiar usuário">${icon('user')}</button>
        <button type="button" class="icon-btn icon-btn-sm" data-action="copy-pass" data-id="${esc(item.id)}" ${item.password ? '' : 'disabled'} aria-label="Copiar senha de ${esc(item.name)}" title="Copiar senha">${icon('key')}</button>
      </span>
    </li>`;
  }

  function sectionHeadHTML(title, actionHTML = '') {
    return `<div class="section-head"><h2 class="section-title">${esc(title)}</h2>${actionHTML}</div>`;
  }

  function homeViewHTML() {
    const { items, projects } = state.vault;
    const projectsById = new Map(projects.map((p) => [p.id, p]));
    const favorites = items.filter((i) => i.favorite);
    const health = passwordHealth();
    const counts = projectCounts();
    const hour = new Date().getHours();
    const greeting = hour < 12 ? 'Bom dia' : hour < 18 ? 'Boa tarde' : 'Boa noite';

    let html = `<header class="page-head">
      <div><p class="eyebrow">${greeting}</p><h1 class="page-title">${esc(state.vault.vault.name)}</h1>
      <p class="page-sub">${plural(items.length, 'credencial protegida', 'credenciais protegidas')} com AES-256-GCM</p></div>
    </header>
    <div class="stats">
      ${statTileHTML({ label: 'Credenciais', value: items.length, iconName: 'key', action: 'nav', nav: 'all' })}
      ${statTileHTML({ label: 'Projetos', value: projects.length, iconName: 'folder', action: 'scroll-projects' })}
      ${statTileHTML({ label: 'Favoritos', value: favorites.length, iconName: 'star', action: 'nav', nav: 'favorites' })}
      ${statTileHTML({ label: 'Precisam de atenção', value: health.size, iconName: 'alert', action: 'nav', nav: 'attention', tone: health.size ? 'warn' : '', hint: health.size ? 'Senhas fracas ou reutilizadas' : 'Nenhum problema encontrado' })}
    </div>`;

    if (!items.length && !projects.length) return html + emptyVaultHTML();

    const recent = items.filter((i) => i.lastUsedAt).sort((a, b) => Date.parse(b.lastUsedAt) - Date.parse(a.lastUsedAt)).slice(0, 5);
    const columns = [];
    if (recent.length) {
      columns.push(`<section class="panel">${sectionHeadHTML('Acessos recentes')}
        <ul class="compact-list">${recent.map((i) => compactRowHTML(i, projectsById, `<span class="muted small">${esc(relativeTime(i.lastUsedAt))}</span>`)).join('')}</ul></section>`);
    }
    columns.push(`<section class="panel">${sectionHeadHTML('Favoritos', favorites.length ? '<button type="button" class="btn-link" data-action="nav" data-nav="favorites">Ver todos</button>' : '')}
      ${favorites.length
        ? `<ul class="compact-list">${favorites.slice(0, 6).map((i) => compactRowHTML(i, projectsById)).join('')}</ul>`
        : `<div class="empty-inline">${icon('star')}<p>Marque credenciais com a estrela para acessá-las rapidamente.</p></div>`}
    </section>`);

    html += `<div class="home-grid ${columns.length === 1 ? 'home-grid-single' : ''}">${columns.join('')}</div>`;

    const projectCards = sortedProjects().map((p) => projectCardHTML(p, counts.get(p.id) || 0));
    if (counts.get('none')) projectCards.push(projectCardHTML(null, counts.get('none')));
    html += `<section class="section" id="projects-section">
      ${sectionHeadHTML('Projetos', `<button type="button" class="btn btn-secondary btn-sm" data-action="new-project">${icon('plus')}Novo projeto</button>`)}
      <div class="project-grid">
        ${projectCards.join('')}
        <button type="button" class="project-card project-card-new" data-action="new-project">
          <span class="project-new-icon">${icon('plus')}</span>
          <span class="project-name">Novo projeto</span>
          <span class="project-desc">Agrupe credenciais por cliente, sistema ou equipe</span>
        </button>
      </div>
    </section>`;
    return html;
  }

  /* ---------------- Lista de credenciais ---------------- */

  function itemsHeading() {
    const { query, filters } = state.ui;
    const keys = activeFilterKeys();
    if (query) return { title: `Resultados para “${query}”`, eyebrow: 'Pesquisa' };
    if (keys.length === 1 && keys[0] === 'project') {
      const project = filters.project === 'none' ? null : findProject(filters.project);
      return { title: project ? project.name : 'Sem projeto', eyebrow: 'Projeto', project, isProject: true };
    }
    if (keys.length === 1 && keys[0] === 'favorites') return { title: 'Favoritos', eyebrow: 'Coleção' };
    if (keys.length === 1 && keys[0] === 'category') return { title: CATEGORY_MAP.get(filters.category).label, eyebrow: 'Categoria' };
    if (keys.length === 1 && keys[0] === 'attention') return { title: 'Precisam de atenção', eyebrow: 'Saúde das senhas' };
    if (keys.length) return { title: 'Credenciais filtradas', eyebrow: 'Filtros' };
    return { title: 'Todas as credenciais', eyebrow: 'Cofre' };
  }

  function projectHeaderHTML(heading, total) {
    const project = heading.project;
    if (!project) {
      return `<header class="page-head project-head">
        <span class="project-icon project-icon-lg pc-slate">${icon('box')}</span>
        <div class="project-head-text"><p class="eyebrow">Projeto</p><h1 class="page-title">Sem projeto</h1>
        <p class="page-sub">${plural(total, 'credencial', 'credenciais')} sem projeto associado</p></div>
        <div class="page-actions"><button type="button" class="btn btn-primary" data-action="new-item">${icon('plus')}<span>Nova credencial</span></button></div>
      </header>`;
    }
    return `<header class="page-head project-head">
      <span class="project-icon project-icon-lg pc-${project.color}">${icon(project.icon)}</span>
      <div class="project-head-text"><p class="eyebrow">Projeto · criado em ${esc(formatDate(project.createdAt))}</p>
        <h1 class="page-title">${esc(project.name)}</h1>
        <p class="page-sub">${project.description ? esc(project.description) : plural(total, 'credencial', 'credenciais')}</p></div>
      <div class="page-actions">
        <button type="button" class="icon-btn" data-action="edit-project" data-id="${esc(project.id)}" aria-label="Editar projeto" title="Editar projeto">${icon('pencil')}</button>
        <button type="button" class="icon-btn icon-btn-danger" data-action="delete-project" data-id="${esc(project.id)}" aria-label="Excluir projeto" title="Excluir projeto">${icon('trash')}</button>
        <button type="button" class="btn btn-primary" data-action="new-item" data-project="${esc(project.id)}">${icon('plus')}<span>Nova credencial</span></button>
      </div>
    </header>`;
  }

  function toolbarHTML(resultCount) {
    const { filters, sort } = state.ui;
    const projectOptions = sortedProjects().map((p) => `<option value="${esc(p.id)}" ${filters.project === p.id ? 'selected' : ''}>${esc(p.name)}</option>`).join('');
    const categoryOptions = CATEGORIES.map((c) => `<option value="${c.id}" ${filters.category === c.id ? 'selected' : ''}>${esc(c.label)}</option>`).join('');
    const sortOptions = [
      ['name-asc', 'Nome (A–Z)'], ['name-desc', 'Nome (Z–A)'],
      ['updated-desc', 'Atualizadas recentemente'], ['updated-asc', 'Atualizadas há mais tempo'],
    ].map(([v, l]) => `<option value="${v}" ${sort === v ? 'selected' : ''}>${l}</option>`).join('');
    const hasFilters = activeFilterKeys().length || state.ui.query;
    return `<div class="toolbar" role="toolbar" aria-label="Filtros e ordenação">
      <div class="toolbar-group">
        <label class="select-wrap"><span class="sr-only">Filtrar por projeto</span>${icon('folder')}
          <select class="select" data-filter="project">
            <option value="all">Todos os projetos</option><option value="none" ${filters.project === 'none' ? 'selected' : ''}>Sem projeto</option>${projectOptions}
          </select></label>
        <label class="select-wrap"><span class="sr-only">Filtrar por categoria</span>${icon('layers')}
          <select class="select" data-filter="category"><option value="all">Todas as categorias</option>${categoryOptions}</select></label>
        <button type="button" class="chip-toggle" data-action="toggle-filter" data-filter-key="favorites" aria-pressed="${filters.favorites}">${icon('star')}Favoritos</button>
        ${filters.attention ? `<button type="button" class="chip-toggle" data-action="toggle-filter" data-filter-key="attention" aria-pressed="true">${icon('alert')}Atenção</button>` : ''}
        ${hasFilters ? `<button type="button" class="btn-link" data-action="clear-filters">Limpar</button>` : ''}
      </div>
      <div class="toolbar-group toolbar-end">
        <span class="result-count" aria-live="polite">${plural(resultCount, 'resultado', 'resultados')}</span>
        <label class="select-wrap"><span class="sr-only">Ordenar</span>${icon('filter')}
          <select class="select" data-sort>${sortOptions}</select></label>
      </div>
    </div>`;
  }

  function itemRowHTML(item, projectsById, health) {
    const project = projectsById.get(item.projectId);
    const category = CATEGORY_MAP.get(item.category);
    const url = toSafeUrl(item.url);
    const sub = [item.username, item.system || (url ? url.host : '')].filter(Boolean).join(' · ') || 'Sem usuário';
    const issues = health.get(item.id);
    return `<li class="row">
      <button type="button" class="row-main" data-action="view-item" data-id="${esc(item.id)}">
        ${avatarHTML(item)}
        <span class="row-text">
          <span class="row-title">${esc(item.name)}${issues ? `<span class="row-flag" title="Senha ${esc(issues.join(' e '))}">${icon('alert')}<span class="sr-only">Senha ${esc(issues.join(' e '))}</span></span>` : ''}</span>
          <span class="row-sub">${esc(sub)}</span>
        </span>
      </button>
      <span class="row-col row-project">${projectChipHTML(project)}</span>
      <span class="row-col row-category">${icon(category.icon)}${esc(category.label)}</span>
      <span class="row-col row-date" title="Atualizada em ${esc(formatDate(item.updatedAt))}">${esc(relativeTime(item.updatedAt))}</span>
      <span class="row-actions">
        <button type="button" class="icon-btn icon-btn-sm" data-action="copy-user" data-id="${esc(item.id)}" ${item.username ? '' : 'disabled'} aria-label="Copiar usuário de ${esc(item.name)}" title="Copiar usuário">${icon('user')}</button>
        <button type="button" class="icon-btn icon-btn-sm" data-action="copy-pass" data-id="${esc(item.id)}" ${item.password ? '' : 'disabled'} aria-label="Copiar senha de ${esc(item.name)}" title="Copiar senha">${icon('key')}</button>
        <button type="button" class="icon-btn icon-btn-sm fav-toggle" data-action="toggle-fav" data-id="${esc(item.id)}" aria-pressed="${item.favorite}" aria-label="${item.favorite ? 'Remover dos favoritos' : 'Adicionar aos favoritos'}: ${esc(item.name)}" title="${item.favorite ? 'Remover dos favoritos' : 'Favoritar'}">${icon('star')}</button>
      </span>
    </li>`;
  }

  function itemsViewHTML() {
    const items = filteredItems();
    const heading = itemsHeading();
    const projectsById = new Map(state.vault.projects.map((p) => [p.id, p]));
    const health = passwordHealth();
    const head = heading.isProject
      ? projectHeaderHTML(heading, items.length)
      : `<header class="page-head"><div><p class="eyebrow">${esc(heading.eyebrow)}</p><h1 class="page-title">${esc(heading.title)}</h1></div>
         <div class="page-actions"><button type="button" class="btn btn-primary" data-action="new-item">${icon('plus')}<span>Nova credencial</span></button></div></header>`;

    const inProjectPage = heading.isProject && heading.project;
    if (!state.vault.items.length && !inProjectPage) return `${head}${emptyVaultHTML()}`;

    let body;
    if (!items.length) {
      const inProject = heading.isProject && heading.project;
      body = `<div class="empty-state">
        <span class="empty-icon">${icon(inProject ? 'folder' : 'search')}</span>
        <h2>${inProject ? 'Este projeto ainda não tem credenciais' : 'Nenhuma credencial encontrada'}</h2>
        <p>${inProject ? 'Adicione uma credencial já vinculada a este projeto.' : 'Tente outros termos de pesquisa ou remova alguns filtros.'}</p>
        <div class="empty-actions">${inProject
          ? `<button type="button" class="btn btn-primary" data-action="new-item" data-project="${esc(heading.project.id)}">${icon('plus')}Adicionar credencial</button>`
          : `<button type="button" class="btn btn-secondary" data-action="clear-filters">Limpar pesquisa e filtros</button>`}</div>
      </div>`;
    } else {
      body = `<div class="list-head" aria-hidden="true"><span>Nome</span><span>Projeto</span><span>Categoria</span><span>Atualizada</span><span></span></div>
        <ul class="item-list">${items.map((i) => itemRowHTML(i, projectsById, health)).join('')}</ul>`;
    }
    return `${head}${toolbarHTML(items.length)}${body}`;
  }

  /* =========================================================================
   * 11. Drawers: detalhes, formulários, gerador e configurações
   * ====================================================================== */

  function recordAccess(item) {
    item.lastUsedAt = nowIso();
    state.softDirty = true;
    scheduleAutosave();
  }

  function detailRowHTML(label, valueHTML, actionsHTML = '') {
    return `<div class="detail-row"><dt>${esc(label)}</dt><dd><div class="detail-value">${valueHTML}</div>${actionsHTML ? `<div class="detail-actions">${actionsHTML}</div>` : ''}</dd></div>`;
  }

  function copyButtonHTML(action, id, label, extra = '') {
    return `<button type="button" class="icon-btn icon-btn-sm" data-action="${action}" data-id="${esc(id)}" ${extra} aria-label="${esc(label)}" title="${esc(label)}">${icon('copy')}</button>`;
  }

  function openItemDetails(id, { silent = false } = {}) {
    const item = findItem(id);
    if (!item) { Toast.show('Credencial não encontrada.', { type: 'error' }); return; }
    if (!silent) recordAccess(item);
    const project = findProject(item.projectId);
    const category = CATEGORY_MAP.get(item.category);
    const url = toSafeUrl(item.url);
    const strength = estimateStrength(item.password);
    const issues = passwordHealth().get(item.id);
    const empty = '<span class="muted">Não informado</span>';

    const urlValue = url
      ? `<a class="detail-link" href="${esc(url.href)}" target="_blank" rel="noopener noreferrer">${esc(displayUrl(url))}${icon('external')}</a>`
      : (item.url ? `<span class="mono">${esc(item.url)}</span>` : empty);

    const historyHTML = item.history.length ? `<details class="history">
        <summary>${icon('history')}Histórico de senhas <span class="badge">${item.history.length}</span></summary>
        <ul class="history-list">${item.history.map((h, index) => `<li>
          <span class="mono masked">••••••••••</span><span class="muted small">substituída ${esc(relativeTime(h.changedAt))}</span>
          <button type="button" class="icon-btn icon-btn-sm" data-action="copy-history" data-id="${esc(item.id)}" data-index="${index}" aria-label="Copiar senha antiga" title="Copiar senha antiga">${icon('copy')}</button>
        </li>`).join('')}</ul></details>` : '';

    const body = `
      <div class="detail-hero">
        ${avatarHTML(item, 'lg')}
        <div class="detail-hero-text">
          <h3 class="detail-name">${esc(item.name)}</h3>
          <div class="detail-tags">
            <span class="badge">${icon(category.icon)}${esc(category.label)}</span>
            ${projectChipHTML(project, { clickable: !!project })}
            ${item.favorite ? `<span class="badge badge-star">${icon('star')}Favorito</span>` : ''}
          </div>
        </div>
      </div>
      <dl class="detail-list">
        ${detailRowHTML('Usuário ou e-mail', item.username ? `<span class="detail-text">${esc(item.username)}</span>` : empty,
          item.username ? copyButtonHTML('copy-user', item.id, 'Copiar usuário') : '')}
        ${detailRowHTML('Senha', item.password ? '<span class="mono secret" data-secret>••••••••••••</span>' : empty,
          item.password ? `<button type="button" class="icon-btn icon-btn-sm" data-action="reveal-secret" data-id="${esc(item.id)}" aria-pressed="false" aria-label="Mostrar senha" title="Mostrar senha">${icon('eye')}</button>${copyButtonHTML('copy-pass', item.id, 'Copiar senha')}` : '')}
        ${item.password ? `<div class="detail-row detail-row-meter"><dt class="sr-only">Força da senha</dt><dd>${strengthMeterHTML('detail-strength')}
          ${issues && issues.includes('reutilizada') ? `<p class="inline-warning">${icon('alert')}Esta senha é usada em outra credencial.</p>` : ''}</dd></div>` : ''}
        ${detailRowHTML('URL', urlValue, url ? `<a class="icon-btn icon-btn-sm" href="${esc(url.href)}" target="_blank" rel="noopener noreferrer" aria-label="Abrir site em nova aba" title="Abrir site">${icon('external')}</a>${copyButtonHTML('copy-url', item.id, 'Copiar URL')}` : '')}
        ${detailRowHTML('Sistema ou serviço', item.system ? `<span class="detail-text">${esc(item.system)}</span>` : empty)}
      </dl>
      <section class="detail-block">
        <h4 class="detail-block-title">${icon('note')}Observações</h4>
        ${item.notes ? `<p class="detail-notes">${esc(item.notes)}</p>` : '<p class="muted">Sem observações.</p>'}
      </section>
      ${historyHTML}
      <dl class="detail-meta">
        <div><dt>Criada em</dt><dd>${esc(formatDate(item.createdAt))}</dd></div>
        <div><dt>Atualizada em</dt><dd>${esc(formatDate(item.updatedAt))}</dd></div>
        <div><dt>Último acesso</dt><dd>${item.lastUsedAt ? esc(relativeTime(item.lastUsedAt)) : '—'}</dd></div>
      </dl>`;

    const footer = `
      <button type="button" class="btn btn-danger-ghost" data-action="delete-item" data-id="${esc(item.id)}">${icon('trash')}<span>Excluir</span></button>
      <span class="spacer"></span>
      <button type="button" class="btn btn-secondary fav-toggle" data-action="toggle-fav" data-id="${esc(item.id)}" aria-pressed="${item.favorite}">${icon('star')}<span>${item.favorite ? 'Desfavoritar' : 'Favoritar'}</span></button>
      <button type="button" class="btn btn-primary" data-action="edit-item" data-id="${esc(item.id)}" data-autofocus>${icon('pencil')}<span>Editar</span></button>`;

    Drawer.open({
      title: 'Detalhes da credencial',
      subtitle: 'Somente visualização',
      body,
      footer,
      kind: 'item-details',
      refId: item.id,
      onMount(drawer) {
        updateStrengthMeter($('#detail-strength', drawer), strength);
      },
    });
  }

  function toggleSecret(button) {
    const item = findItem(button.dataset.id);
    const drawer = Drawer.element();
    if (!item || !drawer) return;
    const secret = $('[data-secret]', drawer);
    const reveal = button.getAttribute('aria-pressed') !== 'true';
    secret.textContent = reveal ? item.password : '••••••••••••';
    secret.classList.toggle('is-revealed', reveal);
    button.setAttribute('aria-pressed', String(reveal));
    button.setAttribute('aria-label', reveal ? 'Ocultar senha' : 'Mostrar senha');
    button.title = reveal ? 'Ocultar senha' : 'Mostrar senha';
    button.innerHTML = icon(reveal ? 'eyeOff' : 'eye');
  }

  /* ---------------- Formulário de credencial ---------------- */

  function categoryChipsHTML(selected) {
    return `<div class="choice-grid" role="radiogroup" aria-label="Categoria">${CATEGORIES.map((c) => `
      <label class="choice">
        <input type="radio" name="category" value="${c.id}" ${c.id === selected ? 'checked' : ''}>
        <span class="choice-body"><span class="choice-icon pc-${c.color}">${icon(c.icon)}</span>${esc(c.label)}</span>
      </label>`).join('')}</div>`;
  }

  function colorSwatchesHTML(name, selected) {
    return `<div class="swatches" role="radiogroup" aria-label="Cor">${PROJECT_COLORS.map((c) => `
      <label class="swatch" title="${esc(c.label)}">
        <input type="radio" name="${name}" value="${c.id}" ${c.id === selected ? 'checked' : ''}>
        <span class="swatch-dot pc-${c.id}"></span><span class="sr-only">${esc(c.label)}</span>
      </label>`).join('')}</div>`;
  }

  function projectOptionsHTML(selectedId) {
    return `<option value="">Sem projeto</option>
      ${sortedProjects().map((p) => `<option value="${esc(p.id)}" ${p.id === selectedId ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}
      <option value="__new__">+ Criar novo projeto…</option>`;
  }

  function generatorPanelHTML(prefix, { showUse = false } = {}) {
    const toggles = [
      ['upper', 'Maiúsculas', 'A–Z'], ['lower', 'Minúsculas', 'a–z'],
      ['digits', 'Números', '0–9'], ['symbols', 'Símbolos', '!@#$'],
      ['avoidAmbiguous', 'Evitar ambíguos', 'I l 1 O 0'],
    ];
    return `<div class="gen" data-gen>
      <div class="gen-output">
        <output class="gen-value" data-gen-value aria-label="Senha gerada"></output>
        <div class="gen-output-actions">
          <button type="button" class="icon-btn" data-gen-refresh aria-label="Gerar outra senha" title="Gerar outra">${icon('refresh')}</button>
          <button type="button" class="icon-btn" data-gen-copy aria-label="Copiar senha gerada" title="Copiar">${icon('copy')}</button>
        </div>
      </div>
      ${strengthMeterHTML()}
      <div class="gen-length">
        <label for="${prefix}-length">Comprimento</label>
        <div class="gen-length-controls">
          <input type="range" id="${prefix}-length" min="8" max="128" step="1" data-gen-range>
          <input type="number" class="input input-sm" min="8" max="128" step="1" data-gen-number aria-label="Comprimento em caracteres">
        </div>
      </div>
      <div class="gen-options">${toggles.map(([key, label, sample]) => `
        <label class="switch-row">
          <span class="switch-text">${esc(label)}<small class="mono">${esc(sample)}</small></span>
          <input type="checkbox" class="switch" data-gen-opt="${key}">
        </label>`).join('')}</div>
      ${showUse ? `<button type="button" class="btn btn-primary btn-block" data-gen-use>${icon('check')}Usar esta senha</button>` : ''}
    </div>`;
  }

  function renderGeneratedValue(output, password) {
    output.innerHTML = [...password].map((ch) => {
      const cls = /\d/.test(ch) ? 'g-d' : /[A-Za-z]/.test(ch) ? '' : 'g-s';
      return cls ? `<span class="${cls}">${esc(ch)}</span>` : esc(ch);
    }).join('');
  }

  /** Monta um gerador de senhas reutilizável (drawer dedicado ou dentro do formulário). */
  function mountGenerator(root, { onUse = null } = {}) {
    const options = Prefs.get('generator');
    const output = $('[data-gen-value]', root);
    const range = $('[data-gen-range]', root);
    const number = $('[data-gen-number]', root);
    const meter = $('.strength', root);
    let current = '';

    function regenerate() {
      current = PasswordGenerator.generate(options);
      renderGeneratedValue(output, current);
      const bits = PasswordGenerator.entropyBits(options);
      const score = scoreFromBits(bits);
      updateStrengthMeter(meter, { score, bits, label: STRENGTH_LABELS[score] });
    }

    function persist() {
      Prefs.set('generator', { ...options });
    }

    function setLength(value) {
      const length = Math.min(128, Math.max(8, Math.trunc(Number(value)) || 8));
      options.length = length;
      range.value = String(length);
      number.value = String(length);
      root.style.setProperty('--range-pct', `${((length - 8) / 120) * 100}%`);
    }

    setLength(options.length);
    for (const toggle of $$('[data-gen-opt]', root)) {
      toggle.checked = !!options[toggle.dataset.genOpt];
      toggle.addEventListener('change', () => {
        const key = toggle.dataset.genOpt;
        options[key] = toggle.checked;
        const anySet = options.upper || options.lower || options.digits || options.symbols;
        if (!anySet) {
          options[key] = true;
          toggle.checked = true;
          Toast.show('Mantenha pelo menos um conjunto de caracteres.', { type: 'info' });
          return;
        }
        persist();
        regenerate();
      });
    }
    range.addEventListener('input', () => { setLength(range.value); regenerate(); });
    range.addEventListener('change', persist);
    number.addEventListener('change', () => { setLength(number.value); persist(); regenerate(); });
    $('[data-gen-refresh]', root).addEventListener('click', regenerate);
    $('[data-gen-copy]', root).addEventListener('click', () => copyWithFeedback(current, 'Senha copiada', true));
    const useButton = $('[data-gen-use]', root);
    if (useButton && onUse) useButton.addEventListener('click', () => onUse(current));
    regenerate();
    return { value: () => current, regenerate };
  }

  function fieldHTML({ id, label, required = false, control, hint = '' }) {
    return `<div class="field">
      <label for="${id}">${esc(label)}${required ? ' <span class="req" aria-hidden="true">*</span>' : ''}</label>
      ${control}
      <p class="field-error" id="${id}-error" hidden></p>
      ${hint ? `<p class="field-hint" id="${id}-hint">${hint}</p>` : ''}
    </div>`;
  }

  function openItemForm(itemId = null, prefill = {}) {
    const existing = itemId ? findItem(itemId) : null;
    if (itemId && !existing) { Toast.show('Credencial não encontrada.', { type: 'error' }); return; }
    const isEdit = !!existing;
    const data = existing ? { ...existing } : {
      name: '', system: '', url: '', username: '', password: prefill.password || '',
      projectId: prefill.projectId && findProject(prefill.projectId) ? prefill.projectId : null,
      category: prefill.category || 'login', notes: '', favorite: false,
    };

    const body = `<form id="item-form" class="form" novalidate autocomplete="off">
      <section class="form-section">
        <h3 class="form-section-title">Identificação</h3>
        ${fieldHTML({ id: 'f-name', label: 'Nome da credencial', required: true, control: `<input type="text" id="f-name" name="name" class="input" maxlength="${LIMITS.name}" placeholder="Ex.: Painel AWS — produção" aria-describedby="f-name-error" data-autofocus>` })}
        <div class="field-row">
          ${fieldHTML({ id: 'f-system', label: 'Sistema ou serviço', control: `<input type="text" id="f-system" name="system" class="input" maxlength="${LIMITS.system}" placeholder="Ex.: Amazon Web Services">` })}
          ${fieldHTML({ id: 'f-url', label: 'URL do sistema', control: `<input type="url" id="f-url" name="url" class="input" maxlength="${LIMITS.url}" placeholder="https://" inputmode="url" spellcheck="false" aria-describedby="f-url-error">` })}
        </div>
      </section>
      <section class="form-section">
        <h3 class="form-section-title">Acesso</h3>
        ${fieldHTML({ id: 'f-username', label: 'Usuário ou e-mail', control: `<input type="text" id="f-username" name="username" class="input" maxlength="${LIMITS.username}" autocomplete="off" spellcheck="false" autocapitalize="off">` })}
        <div class="field">
          <label for="f-password">Senha <span class="req" aria-hidden="true">*</span></label>
          <div class="input-group">
            <input type="password" id="f-password" name="password" class="input mono" maxlength="${LIMITS.password}" autocomplete="new-password" spellcheck="false" autocapitalize="off" aria-describedby="f-password-error">
            ${revealButtonHTML('f-password')}
            <button type="button" class="icon-btn" data-form-generate aria-label="Gerar senha segura" title="Gerar senha segura">${icon('sparkles')}</button>
          </div>
          ${strengthMeterHTML('f-strength')}
          <p class="field-error" id="f-password-error" hidden></p>
          <details class="inline-gen" id="f-gen-details">
            <summary>${icon('settings')}Opções do gerador</summary>
            <div class="inline-gen-body">${generatorPanelHTML('f-gen', { showUse: true })}</div>
          </details>
        </div>
      </section>
      <section class="form-section">
        <h3 class="form-section-title">Organização</h3>
        ${fieldHTML({ id: 'f-project', label: 'Projeto', control: `<select id="f-project" name="projectId" class="input">${projectOptionsHTML(data.projectId)}</select>` })}
        <div class="inline-project" id="f-new-project" hidden>
          ${fieldHTML({ id: 'f-new-project-name', label: 'Nome do novo projeto', required: true, control: `<input type="text" id="f-new-project-name" name="newProjectName" class="input" maxlength="${LIMITS.projectName}" placeholder="Ex.: Cliente Alfa" aria-describedby="f-new-project-name-error">` })}
          <div class="field"><span class="label">Cor</span>${colorSwatchesHTML('newProjectColor', 'blue')}</div>
          <p class="field-hint">O projeto será criado ao salvar a credencial.</p>
        </div>
        <div class="field"><span class="label" id="f-category-label">Categoria</span>${categoryChipsHTML(data.category)}</div>
        <label class="switch-row switch-row-card">
          <span class="switch-text">${icon('star')}Marcar como favorito<small>Aparece na seção de favoritos da visão geral</small></span>
          <input type="checkbox" class="switch" name="favorite" id="f-favorite">
        </label>
      </section>
      <section class="form-section">
        <h3 class="form-section-title">Observações</h3>
        ${fieldHTML({ id: 'f-notes', label: 'Observações', control: `<textarea id="f-notes" name="notes" class="input textarea" rows="4" maxlength="${LIMITS.notes}" placeholder="Informações adicionais, perguntas de segurança, chaves de recuperação…"></textarea>` })}
      </section>
    </form>`;

    const footer = `
      <span class="foot-hint hide-xs"><kbd>Ctrl</kbd> + <kbd>Enter</kbd> para salvar</span>
      <span class="spacer"></span>
      <button type="button" class="btn btn-secondary" data-drawer-cancel>Cancelar</button>
      <button type="submit" class="btn btn-primary" form="item-form" id="item-form-submit">${icon('check')}<span>${isEdit ? 'Salvar alterações' : 'Salvar credencial'}</span></button>`;

    let snapshot = '';
    Drawer.open({
      title: isEdit ? 'Editar credencial' : 'Nova credencial',
      subtitle: isEdit ? existing.name : 'Os dados são criptografados ao salvar o cofre',
      headIcon: icon(isEdit ? 'pencil' : 'plus'),
      body,
      footer,
      kind: 'item-form',
      refId: itemId || '',
      isDirty: () => !!$('#item-form') && formSnapshot($('#item-form')) !== snapshot,
      onMount(drawer) {
        const form = $('#item-form', drawer);
        form.elements.name.value = data.name;
        form.elements.system.value = data.system;
        form.elements.url.value = data.url;
        form.elements.username.value = data.username;
        form.elements.password.value = data.password;
        form.elements.notes.value = data.notes;
        form.elements.favorite.checked = !!data.favorite;
        snapshot = formSnapshot(form);
        bindItemForm(form, drawer, existing);
      },
    });
  }

  function bindItemForm(form, drawer, existing) {
    const passwordInput = form.elements.password;
    const meter = $('#f-strength', drawer);
    const projectSelect = form.elements.projectId;
    const newProjectBox = $('#f-new-project', drawer);
    const refreshMeter = () => updateStrengthMeter(meter, estimateStrength(passwordInput.value));
    const revealPassword = () => {
      if (passwordInput.type === 'password') togglePasswordVisibility($('[data-reveal="f-password"]', drawer));
    };

    refreshMeter();
    passwordInput.addEventListener('input', refreshMeter);

    const details = $('#f-gen-details', drawer);
    let generator = null;
    const ensureGenerator = () => {
      if (!generator) {
        generator = mountGenerator($('[data-gen]', details), {
          onUse(value) {
            passwordInput.value = value;
            revealPassword();
            refreshMeter();
            setFieldError(passwordInput, '');
            details.open = false;
          },
        });
      }
      return generator;
    };
    details.addEventListener('toggle', () => { if (details.open) ensureGenerator(); });

    $('[data-form-generate]', drawer).addEventListener('click', () => {
      passwordInput.value = PasswordGenerator.generate(Prefs.get('generator'));
      revealPassword();
      refreshMeter();
      setFieldError(passwordInput, '');
      Toast.show('Senha segura gerada.', { type: 'info', duration: 1800 });
    });

    projectSelect.addEventListener('change', () => {
      const creating = projectSelect.value === '__new__';
      newProjectBox.hidden = !creating;
      if (creating) form.elements.newProjectName.focus();
    });

    $('[data-drawer-cancel]', drawer).addEventListener('click', () => Drawer.requestClose('cancel'));
    form.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        form.requestSubmit();
      }
    });
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      saveItemForm(form, existing);
    });
  }

  function readItemForm(form) {
    const el = form.elements;
    return {
      name: el.name.value.trim(),
      system: el.system.value.trim(),
      url: el.url.value.trim(),
      username: el.username.value.trim(),
      password: el.password.value,
      projectId: el.projectId.value,
      newProjectName: el.newProjectName.value.trim(),
      newProjectColor: (form.querySelector('input[name="newProjectColor"]:checked') || {}).value || 'blue',
      category: (form.querySelector('input[name="category"]:checked') || {}).value || 'other',
      notes: el.notes.value,
      favorite: el.favorite.checked,
    };
  }

  function projectNameTaken(name, exceptId = null) {
    const target = normalizeText(name.trim());
    return state.vault.projects.some((p) => p.id !== exceptId && normalizeText(p.name) === target);
  }

  function validateItemData(data) {
    const errors = [];
    if (!data.name) errors.push(['name', 'Informe um nome para a credencial.']);
    if (!data.password) errors.push(['password', 'Informe a senha ou gere uma senha segura.']);
    if (data.url && !toSafeUrl(data.url)) errors.push(['url', 'Informe uma URL válida (http ou https).']);
    if (data.projectId === '__new__') {
      if (!data.newProjectName) errors.push(['newProjectName', 'Informe o nome do novo projeto.']);
      else if (projectNameTaken(data.newProjectName)) errors.push(['newProjectName', 'Já existe um projeto com esse nome.']);
    }
    return errors;
  }

  function createProjectRecord({ name, description = '', color = 'blue', iconName = 'folder' }) {
    const ts = nowIso();
    return {
      id: newId(),
      name: name.slice(0, LIMITS.projectName),
      description: description.slice(0, LIMITS.projectDesc),
      color: PROJECT_COLOR_IDS.includes(color) ? color : 'blue',
      icon: PROJECT_ICON_IDS.includes(iconName) ? iconName : 'folder',
      createdAt: ts,
      updatedAt: ts,
    };
  }

  function saveItemForm(form, existing) {
    clearFieldErrors(form);
    const data = readItemForm(form);
    const errors = validateItemData(data);
    if (errors.length) {
      for (const [name, message] of errors) setFieldError(form.elements[name], message);
      form.elements[errors[0][0]].focus();
      return;
    }
    if (existing && !findItem(existing.id)) {
      Toast.show('Esta credencial não existe mais.', { type: 'error' });
      Drawer.close();
      return;
    }
    const ts = nowIso();
    let savedId = existing ? existing.id : newId();
    let createdProject = null;
    commit((vault) => {
      let projectId = data.projectId || null;
      if (projectId === '__new__') {
        createdProject = createProjectRecord({ name: data.newProjectName, color: data.newProjectColor });
        vault.projects.push(createdProject);
        projectId = createdProject.id;
      } else if (projectId && !vault.projects.some((p) => p.id === projectId)) {
        projectId = null;
      }
      const fields = {
        name: data.name.slice(0, LIMITS.name),
        system: data.system.slice(0, LIMITS.system),
        url: data.url.slice(0, LIMITS.url),
        username: data.username.slice(0, LIMITS.username),
        password: data.password.slice(0, LIMITS.password),
        projectId,
        category: CATEGORY_MAP.has(data.category) ? data.category : 'other',
        notes: data.notes.slice(0, LIMITS.notes),
        favorite: data.favorite,
      };
      if (existing) {
        const item = vault.items.find((i) => i.id === existing.id);
        if (item.password && item.password !== fields.password) {
          item.history = [{ password: item.password, changedAt: ts }, ...item.history].slice(0, HISTORY_LIMIT);
        }
        Object.assign(item, fields, { updatedAt: ts });
      } else {
        vault.items.push({ id: savedId, ...fields, createdAt: ts, updatedAt: ts, lastUsedAt: null, history: [] });
      }
    });
    if (createdProject) Toast.show(`Projeto “${createdProject.name}” criado.`, { type: 'info' });
    Toast.show(existing ? 'Alterações salvas.' : 'Credencial adicionada.');
    openItemDetails(savedId, { silent: true });
  }

  async function deleteItem(id) {
    const item = findItem(id);
    if (!item) return;
    const confirmed = await Modal.confirm({
      title: 'Excluir credencial?',
      message: `“${item.name}” será removida do cofre. Você poderá desfazer logo em seguida.`,
      confirmLabel: 'Excluir credencial',
      danger: true,
    });
    if (!confirmed || !findItem(id)) return;
    const index = state.vault.items.indexOf(item);
    commit((vault) => { vault.items.splice(index, 1); });
    const info = Drawer.info();
    if (info && info.refId === id) Drawer.close();
    Toast.show(`“${item.name}” excluída.`, {
      action: {
        label: 'Desfazer',
        onClick: () => {
          if (!state.vault || findItem(item.id)) return;
          if (item.projectId && !findProject(item.projectId)) item.projectId = null;
          commit((vault) => { vault.items.splice(Math.min(index, vault.items.length), 0, item); });
          Toast.show('Exclusão desfeita.');
        },
      },
    });
  }

  function toggleFavorite(id) {
    const item = findItem(id);
    if (!item) return;
    commit(() => { item.favorite = !item.favorite; });
    Toast.show(item.favorite ? 'Adicionada aos favoritos.' : 'Removida dos favoritos.', { duration: 1800 });
    const info = Drawer.info();
    if (info && info.kind === 'item-details' && info.refId === id) openItemDetails(id, { silent: true });
  }

  async function copyItemField(id, field) {
    const item = findItem(id);
    if (!item) return;
    let ok = false;
    if (field === 'username') ok = await copyWithFeedback(item.username, 'Usuário copiado', false);
    else if (field === 'password') ok = await copyWithFeedback(item.password, 'Senha copiada', true);
    else if (field === 'url') {
      const url = toSafeUrl(item.url);
      ok = await copyWithFeedback(url ? url.href : item.url, 'URL copiada', false);
    }
    if (ok) recordAccess(item);
  }

  /* ---------------- Projetos ---------------- */

  function iconChoicesHTML(selected) {
    return `<div class="icon-choices" role="radiogroup" aria-label="Ícone">${PROJECT_ICONS.map((i) => `
      <label class="icon-choice" title="${esc(i.label)}">
        <input type="radio" name="icon" value="${i.id}" ${i.id === selected ? 'checked' : ''}>
        <span class="icon-choice-body">${icon(i.id)}</span><span class="sr-only">${esc(i.label)}</span>
      </label>`).join('')}</div>`;
  }

  function openProjectForm(projectId = null) {
    const existing = projectId ? findProject(projectId) : null;
    if (projectId && !existing) return;
    const isEdit = !!existing;
    const data = existing || { name: '', description: '', color: PROJECT_COLOR_IDS[(state.vault.projects.length + 1) % PROJECT_COLOR_IDS.length], icon: 'folder' };
    const body = `<form id="project-form" class="form" novalidate autocomplete="off">
      <div class="project-preview" id="p-preview">
        <span class="project-icon project-icon-lg" data-preview-icon></span>
        <div><span class="project-name" data-preview-name></span><span class="project-desc" data-preview-desc></span></div>
      </div>
      ${fieldHTML({ id: 'p-name', label: 'Nome do projeto', required: true, control: `<input type="text" id="p-name" name="name" class="input" maxlength="${LIMITS.projectName}" placeholder="Ex.: Cliente Alfa, Infra interna…" aria-describedby="p-name-error" data-autofocus>` })}
      ${fieldHTML({ id: 'p-desc', label: 'Descrição (opcional)', control: `<textarea id="p-desc" name="description" class="input textarea" rows="3" maxlength="${LIMITS.projectDesc}" placeholder="Para que serve este projeto?"></textarea>` })}
      <div class="field"><span class="label">Cor</span>${colorSwatchesHTML('color', data.color)}</div>
      <div class="field"><span class="label">Ícone</span>${iconChoicesHTML(data.icon)}</div>
      ${isEdit ? `<p class="field-hint">Criado em ${esc(formatDate(existing.createdAt))}</p>` : ''}
    </form>`;
    const footer = `
      ${isEdit ? `<button type="button" class="btn btn-danger-ghost" data-action="delete-project" data-id="${esc(existing.id)}">${icon('trash')}<span>Excluir</span></button>` : ''}
      <span class="spacer"></span>
      <button type="button" class="btn btn-secondary" data-drawer-cancel>Cancelar</button>
      <button type="submit" class="btn btn-primary" form="project-form">${icon('check')}<span>${isEdit ? 'Salvar projeto' : 'Criar projeto'}</span></button>`;
    let snapshot = '';
    Drawer.open({
      title: isEdit ? 'Editar projeto' : 'Novo projeto',
      subtitle: isEdit ? existing.name : 'Organize credenciais por cliente, sistema ou equipe',
      headIcon: icon('folder'),
      body,
      footer,
      kind: 'project-form',
      refId: projectId || '',
      isDirty: () => !!$('#project-form') && formSnapshot($('#project-form')) !== snapshot,
      onMount(drawer) {
        const form = $('#project-form', drawer);
        form.elements.name.value = data.name;
        form.elements.description.value = data.description;
        const updatePreview = () => {
          const color = (form.querySelector('input[name="color"]:checked') || {}).value || 'slate';
          const iconName = (form.querySelector('input[name="icon"]:checked') || {}).value || 'folder';
          const preview = $('[data-preview-icon]', drawer);
          preview.className = `project-icon project-icon-lg pc-${color}`;
          preview.innerHTML = icon(iconName);
          $('[data-preview-name]', drawer).textContent = form.elements.name.value.trim() || 'Nome do projeto';
          $('[data-preview-desc]', drawer).textContent = form.elements.description.value.trim() || 'Sem descrição';
        };
        updatePreview();
        form.addEventListener('input', updatePreview);
        form.addEventListener('change', updatePreview);
        snapshot = formSnapshot(form);
        $('[data-drawer-cancel]', drawer).addEventListener('click', () => Drawer.requestClose('cancel'));
        form.addEventListener('submit', (event) => {
          event.preventDefault();
          saveProjectForm(form, existing);
        });
      },
    });
  }

  function saveProjectForm(form, existing) {
    clearFieldErrors(form);
    const name = form.elements.name.value.trim();
    const description = form.elements.description.value.trim();
    const color = (form.querySelector('input[name="color"]:checked') || {}).value || 'slate';
    const iconName = (form.querySelector('input[name="icon"]:checked') || {}).value || 'folder';
    if (!name) { setFieldError(form.elements.name, 'Informe o nome do projeto.'); form.elements.name.focus(); return; }
    if (projectNameTaken(name, existing ? existing.id : null)) {
      setFieldError(form.elements.name, 'Já existe um projeto com esse nome.');
      form.elements.name.focus();
      return;
    }
    if (existing) {
      commit(() => {
        Object.assign(existing, {
          name: name.slice(0, LIMITS.projectName), description: description.slice(0, LIMITS.projectDesc),
          color, icon: iconName, updatedAt: nowIso(),
        });
      });
      Drawer.close();
      Toast.show('Projeto atualizado.');
      return;
    }
    const project = createProjectRecord({ name, description, color, iconName });
    commit((vault) => { vault.projects.push(project); });
    Drawer.close();
    Toast.show(`Projeto “${project.name}” criado.`);
    navigate({ view: 'items', filters: { project: project.id }, clearQuery: true });
  }

  async function deleteProject(id) {
    const project = findProject(id);
    if (!project) return;
    const count = state.vault.items.filter((i) => i.projectId === id).length;
    let decision = { mode: 'unassign', target: null };

    if (count === 0) {
      const ok = await Modal.confirm({
        title: 'Excluir projeto?',
        message: `O projeto “${project.name}” não possui credenciais e será removido.`,
        confirmLabel: 'Excluir projeto',
        danger: true,
      });
      if (!ok) return;
    } else {
      const others = sortedProjects().filter((p) => p.id !== id);
      const body = `<p class="modal-text">O projeto <strong>${esc(project.name)}</strong> contém ${plural(count, 'credencial', 'credenciais')}. O que deseja fazer com elas?</p>
        <fieldset class="radio-list">
          <legend class="sr-only">Destino das credenciais</legend>
          <label class="radio-card"><input type="radio" name="proj-del" value="unassign" checked>
            <span><strong>Mover para “Sem projeto”</strong><small>As credenciais continuam no cofre, sem projeto associado.</small></span></label>
          ${others.length ? `<label class="radio-card"><input type="radio" name="proj-del" value="move">
            <span><strong>Mover para outro projeto</strong>
            <select class="input input-sm" data-target-project aria-label="Projeto de destino">${others.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></span></label>` : ''}
          <label class="radio-card radio-card-danger"><input type="radio" name="proj-del" value="delete">
            <span><strong>Excluir também as credenciais</strong><small>${plural(count, 'credencial será removida', 'credenciais serão removidas')} permanentemente ao salvar.</small></span></label>
        </fieldset>`;
      const result = await Modal.open({
        title: 'Excluir projeto',
        body,
        size: 'md',
        tone: 'danger',
        dismissValue: null,
        onMount(dialog) {
          const select = $('[data-target-project]', dialog);
          if (select) select.addEventListener('change', () => { $('input[value="move"]', dialog).checked = true; });
        },
        actions: [
          { label: 'Cancelar', value: null, autofocus: true },
          {
            label: 'Excluir projeto',
            variant: 'danger',
            getValue: (dialog) => ({
              mode: $('input[name="proj-del"]:checked', dialog).value,
              target: ($('[data-target-project]', dialog) || {}).value || null,
            }),
          },
        ],
      });
      if (!result) return;
      decision = result;
    }

    commit((vault) => {
      vault.projects = vault.projects.filter((p) => p.id !== id);
      if (decision.mode === 'delete') {
        vault.items = vault.items.filter((i) => i.projectId !== id);
      } else {
        const target = decision.mode === 'move' && vault.projects.some((p) => p.id === decision.target) ? decision.target : null;
        const ts = nowIso();
        for (const item of vault.items) {
          if (item.projectId === id) { item.projectId = target; item.updatedAt = ts; }
        }
      }
    });
    if (Drawer.info() && Drawer.info().refId === id) Drawer.close();
    if (state.ui.filters.project === id) navigate({ view: 'home', filters: {} });
    const messages = {
      unassign: `Projeto excluído. ${count ? 'Credenciais movidas para “Sem projeto”.' : ''}`,
      move: 'Projeto excluído e credenciais movidas.',
      delete: `Projeto e ${plural(count, 'credencial excluídos', 'credenciais excluídos')}.`,
    };
    Toast.show(messages[decision.mode].trim());
  }

  /* ---------------- Gerador (drawer dedicado) ---------------- */

  function openGeneratorDrawer() {
    const body = `${generatorPanelHTML('g')}
      <p class="field-hint gen-note">${icon('shield')}<span>Senhas geradas localmente com <code>crypto.getRandomValues()</code>, sem viés de módulo. Nada é armazenado.</span></p>`;
    const footer = `<span class="spacer"></span>
      <button type="button" class="btn btn-secondary" data-gen-new-item>${icon('plus')}<span>Nova credencial com esta senha</span></button>
      <button type="button" class="btn btn-primary" data-gen-copy-foot data-autofocus>${icon('copy')}<span>Copiar senha</span></button>`;
    Drawer.open({
      title: 'Gerador de senhas',
      subtitle: 'Fonte criptograficamente segura',
      headIcon: icon('sparkles'),
      body,
      footer,
      kind: 'generator',
      onMount(drawer) {
        const generator = mountGenerator($('[data-gen]', drawer));
        $('[data-gen-copy-foot]', drawer).addEventListener('click', () => copyWithFeedback(generator.value(), 'Senha copiada', true));
        $('[data-gen-new-item]', drawer).addEventListener('click', () => openItemForm(null, { password: generator.value() }));
      },
    });
  }

  /* ---------------- Configurações ---------------- */

  function openSettingsDrawer() {
    const s = state.session;
    const fsa = s.mode === 'fsa';
    const iterationOptions = KDF_ITERATION_CHOICES.map((n) => `<option value="${n}" ${n === s.kdf.iterations ? 'selected' : ''}>${n.toLocaleString('pt-BR')}${n === KDF_DEFAULT_ITERATIONS ? ' (recomendado)' : ''}</option>`).join('');
    const lockOptions = [[5, '5 minutos'], [15, '15 minutos'], [30, '30 minutos'], [60, '1 hora'], [0, 'Nunca']]
      .map(([v, l]) => `<option value="${v}" ${Prefs.get('autoLockMinutes') === v ? 'selected' : ''}>${l}</option>`).join('');
    const theme = Prefs.get('theme');

    const body = `
      <section class="settings-section">
        <h3 class="form-section-title">Cofre</h3>
        <form id="s-name-form" class="inline-form" novalidate>
          ${fieldHTML({ id: 's-name', label: 'Nome do cofre', control: `<div class="input-group input-group-btn"><input type="text" id="s-name" name="vaultName" class="input" maxlength="${LIMITS.vaultName}" aria-describedby="s-name-error"><button type="submit" class="btn btn-secondary btn-sm">Renomear</button></div>` })}
        </form>
        <dl class="kv">
          <div><dt>Arquivo</dt><dd class="mono-name" id="s-file"></dd></div>
          <div><dt>Armazenamento</dt><dd>${fsa ? 'Gravação direta no arquivo (File System Access API)' : 'Exportação manual (download a cada salvamento)'}</dd></div>
          <div><dt>Criado em</dt><dd>${esc(formatDate(s.createdAt))}</dd></div>
          <div><dt>Identificador</dt><dd class="mono">${esc(s.vaultId.slice(0, 8))}…</dd></div>
        </dl>
      </section>
      <section class="settings-section">
        <h3 class="form-section-title">Salvamento e backup</h3>
        <label class="switch-row switch-row-card ${fsa ? '' : 'is-disabled'}">
          <span class="switch-text">Salvar automaticamente<small>${fsa ? 'Grava no arquivo logo após cada alteração.' : 'Indisponível no modo exportação manual.'}</small></span>
          <input type="checkbox" class="switch" id="s-autosave" ${fsa && Prefs.get('autosave') ? 'checked' : ''} ${fsa ? '' : 'disabled'}>
        </label>
        <div class="button-stack">
          <button type="button" class="btn btn-secondary" data-action="save">${icon(fsa ? 'save' : 'download')}<span>${fsa ? 'Salvar agora' : 'Baixar arquivo atualizado'}</span></button>
          ${FileIO.supportsDirectWrite ? `<button type="button" class="btn btn-secondary" data-action="save-as">${icon('file')}<span>Salvar como…</span></button>` : ''}
          <button type="button" class="btn btn-secondary" data-action="export-backup">${icon('download')}<span>Exportar backup criptografado</span></button>
        </div>
        <p class="field-hint">O backup é o mesmo envelope criptografado do cofre, com data no nome. Guarde cópias em mais de um local.</p>
      </section>
      <section class="settings-section">
        <h3 class="form-section-title">Segurança</h3>
        <div class="field">
          <label for="s-autolock">Bloquear automaticamente após inatividade</label>
          <select id="s-autolock" class="input">${lockOptions}</select>
        </div>
        <label class="switch-row switch-row-card">
          <span class="switch-text">Limpar área de transferência<small>Remove a senha copiada após 30 segundos (quando o navegador permitir).</small></span>
          <input type="checkbox" class="switch" id="s-clipboard" ${Prefs.get('clearClipboard') ? 'checked' : ''}>
        </label>
        <div class="crypto-card">
          <div><span class="crypto-k">Cifra</span><span class="crypto-v">AES-256-GCM · IV de 96 bits por gravação</span></div>
          <div><span class="crypto-k">Derivação</span><span class="crypto-v">PBKDF2-SHA-256 · ${s.kdf.iterations.toLocaleString('pt-BR')} iterações</span></div>
          <div><span class="crypto-k">Salt</span><span class="crypto-v">128 bits aleatórios</span></div>
        </div>
        <details class="advanced">
          <summary>${icon('key')}Alterar senha mestra ou iterações</summary>
          <form id="s-password-form" class="form" novalidate autocomplete="off">
            ${fieldHTML({ id: 's-current', label: 'Senha mestra atual', required: true, control: `<div class="input-group"><input type="password" id="s-current" name="current" class="input" autocomplete="off" aria-describedby="s-current-error">${revealButtonHTML('s-current')}</div>` })}
            <div class="field">
              <label for="s-new">Nova senha mestra <span class="req" aria-hidden="true">*</span></label>
              <div class="input-group"><input type="password" id="s-new" name="next" class="input" autocomplete="new-password" aria-describedby="s-new-error">${revealButtonHTML('s-new')}</div>
              ${strengthMeterHTML('s-new-strength')}
              <p class="field-error" id="s-new-error" hidden></p>
            </div>
            ${fieldHTML({ id: 's-confirm', label: 'Confirmar nova senha', required: true, control: `<div class="input-group"><input type="password" id="s-confirm" name="confirm" class="input" autocomplete="new-password" aria-describedby="s-confirm-error">${revealButtonHTML('s-confirm')}</div>` })}
            ${fieldHTML({ id: 's-iterations', label: 'Iterações do PBKDF2', control: `<select id="s-iterations" name="iterations" class="input">${iterationOptions}</select>` })}
            <p class="field-hint">Um novo salt é gerado e o cofre é recriptografado e salvo imediatamente. Para manter a mesma senha e só mudar as iterações, repita a senha atual.</p>
            <button type="submit" class="btn btn-primary" id="s-password-submit"><span class="spinner" aria-hidden="true"></span><span class="btn-label">Alterar e salvar</span></button>
          </form>
        </details>
      </section>
      <section class="settings-section">
        <h3 class="form-section-title">Aparência</h3>
        <div class="segmented" role="radiogroup" aria-label="Tema">
          ${[['system', 'Sistema'], ['light', 'Claro'], ['dark', 'Escuro']].map(([v, l]) => `
            <label class="segmented-item"><input type="radio" name="s-theme" value="${v}" ${theme === v ? 'checked' : ''}><span>${l}</span></label>`).join('')}
        </div>
      </section>`;

    Drawer.open({
      title: 'Configurações',
      subtitle: state.vault.vault.name,
      headIcon: icon('settings'),
      body,
      kind: 'settings',
      isDirty: () => {
        const form = $('#s-password-form');
        return !!form && ['current', 'next', 'confirm'].some((n) => form.elements[n].value);
      },
      onMount(drawer) {
        $('#s-file', drawer).textContent = s.fileName;
        const nameForm = $('#s-name-form', drawer);
        nameForm.elements.vaultName.value = state.vault.vault.name;
        nameForm.addEventListener('submit', (event) => {
          event.preventDefault();
          const value = nameForm.elements.vaultName.value.trim();
          if (!value) { setFieldError(nameForm.elements.vaultName, 'Informe um nome.'); return; }
          setFieldError(nameForm.elements.vaultName, '');
          if (value === state.vault.vault.name) return;
          commit((vault) => { vault.vault.name = value.slice(0, LIMITS.vaultName); });
          $('.drawer-subtitle', drawer).textContent = state.vault.vault.name;
          Toast.show('Cofre renomeado.');
        });
        $('#s-autosave', drawer).addEventListener('change', (event) => {
          Prefs.set('autosave', event.target.checked);
          if (event.target.checked && state.dirty) scheduleAutosave();
          renderSaveStatus();
        });
        $('#s-autolock', drawer).addEventListener('change', (event) => {
          Prefs.set('autoLockMinutes', Number(event.target.value));
          Toast.show('Preferência de bloqueio atualizada.', { duration: 1800 });
        });
        $('#s-clipboard', drawer).addEventListener('change', (event) => Prefs.set('clearClipboard', event.target.checked));
        for (const radio of $$('input[name="s-theme"]', drawer)) {
          radio.addEventListener('change', () => { Prefs.set('theme', radio.value); applyTheme(); });
        }
        const pwForm = $('#s-password-form', drawer);
        pwForm.elements.next.addEventListener('input', () => updateStrengthMeter($('#s-new-strength', drawer), estimateStrength(pwForm.elements.next.value)));
        pwForm.addEventListener('submit', (event) => {
          event.preventDefault();
          handleChangeMasterPassword(pwForm);
        });
      },
    });
  }

  async function handleChangeMasterPassword(form) {
    clearFieldErrors(form);
    const { current, next, confirm, iterations } = form.elements;
    const errors = [];
    if (!current.value) errors.push([current, 'Informe a senha mestra atual.']);
    if ([...next.value].length < MIN_MASTER_LENGTH) errors.push([next, `Use pelo menos ${MIN_MASTER_LENGTH} caracteres.`]);
    else if (estimateStrength(next.value).score < 2) errors.push([next, 'Senha muito previsível.']);
    if (confirm.value !== next.value) errors.push([confirm, 'As senhas não coincidem.']);
    if (errors.length) {
      for (const [input, message] of errors) setFieldError(input, message);
      errors[0][0].focus();
      return;
    }
    const session = state.session;
    const button = $('#s-password-submit');
    setButtonLoading(button, true, 'Recriptografando…');
    const previous = { key: session.key, kdf: { ...session.kdf } };
    try {
      const envelope = parseEnvelope(session.lastEnvelopeText);
      const checkKey = await VaultCrypto.deriveKey(current.value, base64ToBytes(envelope.kdf.salt), envelope.kdf.iterations);
      await VaultCrypto.open(checkKey, envelope); // confirma a senha atual
      const salt = VaultCrypto.randomBytes(SALT_BYTES);
      const newIterations = Number(iterations.value) || KDF_DEFAULT_ITERATIONS;
      const newKey = await VaultCrypto.deriveKey(next.value, salt, newIterations);
      session.key = newKey;
      session.kdf = { iterations: newIterations, salt: bytesToBase64(salt) };
      markDirty();
      const saved = await saveVault({ interactive: true });
      if (!saved) {
        session.key = previous.key;
        session.kdf = previous.kdf;
        Toast.show('A senha não foi alterada porque o cofre não pôde ser salvo.', { type: 'error', duration: 5000 });
        return;
      }
      for (const input of [current, next, confirm]) input.value = '';
      Drawer.close();
      Toast.show('Senha mestra alterada e cofre recriptografado.');
    } catch (error) {
      session.key = previous.key;
      session.kdf = previous.kdf;
      if (error instanceof VaultError && error.code === 'decrypt-failed') {
        setFieldError(current, 'Senha mestra atual incorreta.');
        current.focus();
      } else {
        reportError('alterar senha', error);
        Toast.show(errorMessage(error, 'Não foi possível alterar a senha.'), { type: 'error' });
      }
    } finally {
      setButtonLoading(button, false, 'Alterar e salvar');
    }
  }

  /* =========================================================================
   * 12. Ações, atalhos e inicialização
   * ====================================================================== */

  function openSidebar() {
    $('#app').classList.add('sidebar-open');
    const first = $('#sidebar .nav-item');
    if (first) first.focus();
  }

  function closeSidebar() {
    $('#app').classList.remove('sidebar-open');
  }

  const NAV_TARGETS = {
    home: { view: 'home', filters: {} },
    all: { view: 'items', filters: {} },
    favorites: { view: 'items', filters: { favorites: true } },
    attention: { view: 'items', filters: { attention: true } },
  };

  const ACTIONS = {
    // Tela de acesso
    'auth-open': () => chooseExistingFile(),
    'auth-reopen': () => reopenRecentFile(),
    'auth-create-start': () => showAuthScreen('create'),
    'auth-back': () => showAuthScreen('welcome'),
    // Gerais
    'toggle-theme': () => toggleTheme(),
    lock: () => lockVault({ reason: 'manual' }),
    save: () => saveVault({ interactive: true }),
    'save-as': () => saveAsNewFile(),
    'export-backup': () => exportBackup(),
    'open-sidebar': () => openSidebar(),
    'close-sidebar': () => closeSidebar(),
    'open-settings': () => { closeSidebar(); openSettingsDrawer(); },
    'open-generator': () => { closeSidebar(); openGeneratorDrawer(); },
    // Navegação
    nav: (el) => navigate({ ...NAV_TARGETS[el.dataset.nav], clearQuery: true }),
    'open-project': (el) => { if (Drawer.isOpen()) Drawer.close(); navigate({ view: 'items', filters: { project: el.dataset.id }, clearQuery: true }); },
    'open-category': (el) => navigate({ view: 'items', filters: { category: el.dataset.id }, clearQuery: true }),
    'scroll-projects': () => {
      const section = $('#projects-section');
      if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },
    'toggle-filter': (el) => {
      const key = el.dataset.filterKey;
      state.ui.filters[key] = !state.ui.filters[key];
      state.ui.view = 'items';
      renderApp();
      const again = $(`[data-filter-key="${key}"]`);
      if (again) again.focus();
    },
    'clear-filters': () => navigate({ view: 'items', filters: {}, clearQuery: true }),
    // Credenciais
    'new-item': (el) => {
      closeSidebar();
      const projectId = el.dataset.project || (state.ui.view === 'items' && activeFilterKeys().length === 1 && state.ui.filters.project !== 'all' && state.ui.filters.project !== 'none' ? state.ui.filters.project : null);
      openItemForm(null, { projectId, category: state.ui.filters.category !== 'all' ? state.ui.filters.category : undefined });
    },
    'view-item': (el) => openItemDetails(el.dataset.id),
    'edit-item': (el) => openItemForm(el.dataset.id),
    'delete-item': (el) => deleteItem(el.dataset.id),
    'toggle-fav': (el) => toggleFavorite(el.dataset.id),
    'copy-user': (el) => copyItemField(el.dataset.id, 'username'),
    'copy-pass': (el) => copyItemField(el.dataset.id, 'password'),
    'copy-url': (el) => copyItemField(el.dataset.id, 'url'),
    'copy-history': (el) => {
      const item = findItem(el.dataset.id);
      const entry = item && item.history[Number(el.dataset.index)];
      if (entry) copyWithFeedback(entry.password, 'Senha antiga copiada', true);
    },
    'reveal-secret': (el) => toggleSecret(el),
    // Projetos
    'new-project': () => { closeSidebar(); openProjectForm(); },
    'edit-project': (el) => openProjectForm(el.dataset.id),
    'delete-project': (el) => deleteProject(el.dataset.id),
  };

  const VAULT_ACTIONS = new Set(Object.keys(ACTIONS).filter((k) => !k.startsWith('auth-') && k !== 'toggle-theme'));

  function handleClick(event) {
    const reveal = event.target.closest('[data-reveal]');
    if (reveal) { togglePasswordVisibility(reveal); return; }
    const trigger = event.target.closest('[data-action]');
    if (!trigger || trigger.disabled) return;
    const action = ACTIONS[trigger.dataset.action];
    if (!action) return;
    if (VAULT_ACTIONS.has(trigger.dataset.action) && !state.vault) return;
    event.preventDefault();
    Promise.resolve(action(trigger)).catch((error) => {
      reportError(`ação ${trigger.dataset.action}`, error);
      Toast.show('Não foi possível concluir a ação.', { type: 'error' });
    });
  }

  function handleChange(event) {
    const target = event.target;
    if (!state.vault) return;
    if (target.matches('[data-filter]')) {
      state.ui.filters[target.dataset.filter] = target.value;
      state.ui.view = 'items';
      renderApp();
      const again = $(`[data-filter="${target.dataset.filter}"]`);
      if (again) again.focus();
    } else if (target.matches('[data-sort]')) {
      state.ui.sort = target.value;
      Prefs.set('sort', target.value);
      renderApp();
      const again = $('[data-sort]');
      if (again) again.focus();
    }
  }

  function isTypingTarget(el) {
    return el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
  }

  function handleKeydown(event) {
    if (Modal.handleKey(event)) return;
    if (Drawer.handleKey(event)) return;
    if (!state.vault) return;
    const mod = event.ctrlKey || event.metaKey;
    if (mod && event.key.toLowerCase() === 's') {
      event.preventDefault();
      saveVault({ interactive: true });
      return;
    }
    if (Drawer.isOpen()) return;
    if (event.key === 'Escape') {
      if ($('#app').classList.contains('sidebar-open')) { closeSidebar(); return; }
      if (document.activeElement === $('#global-search') && $('#global-search').value) {
        $('#global-search').value = '';
        applySearch('');
      }
      return;
    }
    if (isTypingTarget(document.activeElement)) return;
    if (event.key === '/' || (mod && event.key.toLowerCase() === 'k')) {
      event.preventDefault();
      $('#global-search').focus();
      $('#global-search').select();
    } else if (event.key.toLowerCase() === 'n' && !mod && !event.altKey) {
      event.preventDefault();
      openItemForm(null, {});
    }
  }

  function applySearch(value) {
    if (!state.vault) return;
    state.ui.query = value.trim();
    if (state.ui.query) state.ui.view = 'items';
    renderApp();
  }

  function setupCreateForm() {
    $('#create-iterations').innerHTML = KDF_ITERATION_CHOICES
      .map((n) => `<option value="${n}" ${n === KDF_DEFAULT_ITERATIONS ? 'selected' : ''}>${n.toLocaleString('pt-BR')}${n === KDF_DEFAULT_ITERATIONS ? ' (recomendado)' : ''}</option>`).join('');
    const password = $('#create-password');
    password.addEventListener('input', () => {
      updateStrengthMeter($('#create-strength'), estimateStrength(password.value), `Mínimo de ${MIN_MASTER_LENGTH} caracteres`);
    });
    for (const input of $$('#auth-create input')) {
      input.addEventListener('input', () => setFieldError(input, ''));
      input.addEventListener('change', () => setFieldError(input, ''));
    }
    $('#auth-create').addEventListener('submit', handleCreateSubmit);
  }

  function setupUnlockForm() {
    const input = $('#unlock-password');
    $('#auth-unlock').addEventListener('submit', handleUnlockSubmit);
    input.addEventListener('input', () => showFormAlert($('#unlock-error'), ''));
    const capsCheck = (event) => {
      if (typeof event.getModifierState === 'function') $('#unlock-caps').hidden = !event.getModifierState('CapsLock');
    };
    input.addEventListener('keydown', capsCheck);
    input.addEventListener('keyup', capsCheck);
    input.addEventListener('blur', () => { $('#unlock-caps').hidden = true; });
  }

  function setupDragAndDrop() {
    const auth = $('#auth');
    let depth = 0;
    auth.addEventListener('dragenter', (event) => {
      if (!event.dataTransfer || !Array.from(event.dataTransfer.types).includes('Files')) return;
      event.preventDefault();
      depth += 1;
      auth.classList.add('is-dragging');
    });
    auth.addEventListener('dragover', (event) => { event.preventDefault(); });
    auth.addEventListener('dragleave', () => {
      depth = Math.max(0, depth - 1);
      if (!depth) auth.classList.remove('is-dragging');
    });
    auth.addEventListener('drop', async (event) => {
      event.preventDefault();
      depth = 0;
      auth.classList.remove('is-dragging');
      const item = event.dataTransfer.items && event.dataTransfer.items[0];
      if (item && FileIO.supportsDirectWrite && typeof item.getAsFileSystemHandle === 'function') {
        try {
          const handle = await item.getAsFileSystemHandle();
          if (handle && handle.kind === 'file') { await loadPendingFile({ handle }); return; }
        } catch { /* cai para o arquivo simples */ }
      }
      const file = event.dataTransfer.files && event.dataTransfer.files[0];
      if (file) await loadPendingFile({ file });
    });
  }

  function showBootError(message) {
    $('#boot-error-message').textContent = message;
    $('#boot-error').hidden = false;
    $('#auth').hidden = true;
  }

  function init() {
    applyTheme();
    darkQuery.addEventListener('change', applyTheme);
    hydrateIcons();

    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      showBootError('Este navegador ou endereço não oferece a Web Crypto API. Abra o Arca pelo endereço http://127.0.0.1 exibido pelo script iniciar-cofre.sh, em um navegador atualizado.');
      return;
    }

    document.addEventListener('click', handleClick);
    document.addEventListener('change', handleChange);
    document.addEventListener('keydown', handleKeydown);
    $('#global-search').addEventListener('input', debounce((event) => applySearch(event.target.value), 120));
    window.addEventListener('beforeunload', (event) => {
      if (state.dirty) {
        event.preventDefault();
        event.returnValue = '';
      }
    });
    setInterval(() => { if (state.session && !state.saving) renderSaveStatus(); }, 30000);

    setupCreateForm();
    setupUnlockForm();
    setupDragAndDrop();

    if (!FileIO.supportsDirectWrite) {
      const notice = $('#auth-compat');
      notice.innerHTML = `${icon('info')}<span>Este navegador não permite gravar diretamente em arquivos. O cofre funciona normalmente, mas cada salvamento gera um <strong>download</strong> do arquivo atualizado. Para gravação direta, use Chrome, Edge ou outro navegador Chromium.</span>`;
      notice.hidden = false;
    }
    showAuthScreen('welcome');
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
