/*
 * Arca — cofre de senhas local
 * JavaScript puro + Web Crypto API. Nenhuma dependência externa (os ícones de
 * projeto são paths vetoriais do Lucide, embutidos aqui, não carregados via CDN).
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
  /* Ícones de projeto: nomes do pacote Lucide (https://lucide.dev), carregado via
   * CDN (ver index.html) e renderizados por `projectIcon()`. PROJECT_ICON_COMMON é o
   * preview padrão (5x10); PROJECT_ICON_ALL é o conjunto pesquisável mais amplo. */
  const PROJECT_ICON_COMMON = [
    'Folder', 'FolderKanban', 'Briefcase', 'Code', 'Server', 'Database', 'Globe', 'Home',
    'ShoppingCart', 'Landmark', 'Users', 'Rocket', 'Key', 'Mail', 'Heart', 'BookOpen',
    'Gamepad2', 'Camera', 'Music', 'Palette', 'Plane', 'Leaf', 'Star', 'Lock',
    'Shield', 'Settings', 'Calendar', 'Clock', 'FileText', 'Cloud', 'Smartphone', 'Laptop',
    'Monitor', 'Wifi', 'CreditCard', 'Wallet', 'Gift', 'Coffee', 'Pizza', 'Car',
    'Bike', 'Dumbbell', 'Stethoscope', 'GraduationCap', 'Building', 'Factory', 'Truck', 'Package',
    'Tag', 'Flag',
  ];
  const PROJECT_ICON_ALL = [
    'Activity', 'AlarmClock', 'AlertTriangle', 'Ambulance', 'Anchor', 'Antenna', 'Apple', 'Archive',
    'AtSign', 'Atom', 'Award', 'Baby', 'Backpack', 'BadgeCheck', 'Banknote', 'BarChart3',
    'Barcode', 'Battery', 'BatteryCharging', 'Bed', 'Beer', 'Bell', 'Bike', 'Binary',
    'Bluetooth', 'Book', 'BookOpen', 'Bookmark', 'Bot', 'Box', 'Boxes', 'Braces',
    'Brain', 'Briefcase', 'Bug', 'Building', 'Building2', 'Bus', 'Cake', 'Calculator',
    'Calendar', 'CalendarCheck', 'CalendarClock', 'CalendarDays', 'Camera', 'Car', 'CheckSquare', 'ChefHat',
    'Cherry', 'CircleDollarSign', 'Clapperboard', 'ClipboardCheck', 'ClipboardList', 'Clock', 'Clock3', 'Cloud',
    'CloudCog', 'CloudLightning', 'CloudRain', 'CloudSnow', 'Code', 'Code2', 'Coffee', 'Cog',
    'Coins', 'Compass', 'Cpu', 'CreditCard', 'Crown', 'Database', 'Dice5', 'DollarSign',
    'DoorOpen', 'Drill', 'Droplet', 'Droplets', 'Dumbbell', 'Eye', 'EyeOff', 'Factory',
    'FileBox', 'FileCode', 'FileSignature', 'FileText', 'Files', 'Film', 'Fingerprint', 'Flag',
    'Flame', 'FlaskConical', 'Flower', 'Flower2', 'Folder', 'FolderKanban', 'FolderOpen', 'Footprints',
    'Fuel', 'Gamepad2', 'Gavel', 'Gem', 'Gift', 'GitBranch', 'GitCommit', 'GitMerge',
    'GitPullRequest', 'Glasses', 'Globe', 'GraduationCap', 'Grid3x3', 'Guitar', 'Hammer', 'Handshake',
    'HardDrive', 'Headphones', 'Heart', 'HeartHandshake', 'HeartPulse', 'HelpCircle', 'Home', 'Hospital',
    'Hourglass', 'House', 'IceCream', 'Image', 'Inbox', 'Info', 'Kanban', 'Key',
    'KeyRound', 'Keyboard', 'Lamp', 'Landmark', 'Laptop', 'Layers', 'LayoutDashboard', 'LayoutGrid',
    'Leaf', 'Library', 'Lightbulb', 'LineChart', 'ListTodo', 'Lock', 'Luggage', 'Mail',
    'Map', 'MapPin', 'MapPinned', 'Medal', 'Megaphone', 'MessageCircle', 'MessageSquare', 'Mic',
    'Microscope', 'Milestone', 'Monitor', 'Moon', 'Mountain', 'Music', 'Music2', 'Navigation',
    'Network', 'Notebook', 'Package', 'PackageCheck', 'PackageOpen', 'Paintbrush', 'Paintbrush2', 'Palette',
    'Palmtree', 'Paperclip', 'ParkingCircle', 'ParkingSquare', 'PartyPopper', 'PencilRuler', 'Percent', 'Phone',
    'PhoneCall', 'PieChart', 'PiggyBank', 'Pill', 'Pin', 'Pizza', 'Plane', 'PlaneTakeoff',
    'Plug', 'Presentation', 'Printer', 'Puzzle', 'QrCode', 'Radio', 'Rainbow', 'Receipt',
    'Refrigerator', 'Rocket', 'Router', 'Rss', 'Ruler', 'Salad', 'Sandwich', 'Satellite',
    'Scale', 'Scan', 'ScanFace', 'School', 'Scissors', 'Send', 'Server', 'Settings',
    'Shapes', 'Share2', 'Shield', 'ShieldAlert', 'ShieldCheck', 'Ship', 'Shirt', 'ShoppingBag',
    'ShoppingCart', 'Signal', 'Signpost', 'SlidersHorizontal', 'Smartphone', 'Smile', 'Snowflake', 'Sofa',
    'Soup', 'Sparkles', 'SprayCan', 'Sprout', 'Star', 'Stethoscope', 'Sticker', 'Store',
    'Sun', 'Sunrise', 'Sunset', 'Syringe', 'Tag', 'Tags', 'Target', 'Tent',
    'Terminal', 'Thermometer', 'ThumbsUp', 'Timer', 'Toothbrush', 'TrafficCone', 'Train', 'Trees', 'TrendingUp',
    'Trophy', 'Truck', 'Tv', 'Umbrella', 'Unlock', 'Usb', 'User', 'UserCheck',
    'UserCircle', 'UserPlus', 'Users', 'Utensils', 'UtensilsCrossed', 'Wallet', 'Warehouse', 'WashingMachine',
    'Watch', 'Waves', 'Webhook', 'Wifi', 'Wind', 'Wine', 'Workflow', 'Wrench',
    'Zap',
  ];
  const PROJECT_ICON_SET = new Set(PROJECT_ICON_ALL);
  const DEFAULT_PROJECT_ICON = 'Folder';

  /* Ícones antigos (desenhados à mão, antes do Lucide) — mantidos para migrar
   * projetos salvos em versões anteriores do cofre. */
  const LEGACY_PROJECT_ICON_MAP = {
    folder: 'Folder', briefcase: 'Briefcase', code: 'Code', server: 'Server',
    globe: 'Globe', home: 'Home', cart: 'ShoppingCart', bank: 'Landmark',
    users: 'Users', rocket: 'Rocket', key: 'Key', mail: 'Mail', heart: 'Heart',
    book: 'BookOpen', gamepad: 'Gamepad2', camera: 'Camera', music: 'Music',
    palette: 'Palette', plane: 'Plane', leaf: 'Leaf',
  };

  function normalizeProjectIcon(value) {
    if (PROJECT_ICON_SET.has(value)) return value;
    if (Object.prototype.hasOwnProperty.call(LEGACY_PROJECT_ICON_MAP, value)) return LEGACY_PROJECT_ICON_MAP[value];
    return DEFAULT_PROJECT_ICON;
  }

  const PROJECT_ICON_LABELS = {
    Folder: 'Pasta', FolderKanban: 'Projeto', Briefcase: 'Trabalho', Code: 'Código',
    Server: 'Servidor', Database: 'Banco de dados', Globe: 'Web', Home: 'Casa',
    ShoppingCart: 'Compras', Landmark: 'Finanças', Users: 'Equipe', Rocket: 'Lançamento',
    Key: 'Segurança', Mail: 'E-mail', Heart: 'Favorito', BookOpen: 'Estudo',
    Gamepad2: 'Jogos', Camera: 'Mídia', Music: 'Música', Palette: 'Design',
    Plane: 'Viagem', Leaf: 'Saúde', Star: 'Destaque', Lock: 'Privado',
    Shield: 'Proteção', Settings: 'Configurações', Calendar: 'Agenda', Clock: 'Tempo',
    FileText: 'Documentos', Cloud: 'Nuvem', Smartphone: 'Celular', Laptop: 'Notebook',
    Monitor: 'Computador', Wifi: 'Rede', CreditCard: 'Cartão', Wallet: 'Carteira',
    Gift: 'Presente', Coffee: 'Café', Pizza: 'Alimentação', Car: 'Carro',
    Bike: 'Bicicleta', Dumbbell: 'Fitness', Stethoscope: 'Médico', GraduationCap: 'Educação',
    Building: 'Empresa', Factory: 'Indústria', Truck: 'Logística', Package: 'Produto',
    Tag: 'Etiqueta', Flag: 'Meta', Toothbrush: 'Escova de dente',
  };

  function humanizeIconName(name) {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');
  }

  function projectIconLabel(name) {
    return PROJECT_ICON_LABELS[name] || humanizeIconName(name);
  }

  function normalizeSearchText(value) {
    return String(value ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  }

  function searchProjectIcons(query) {
    const q = normalizeSearchText(query).trim();
    if (!q) return [];
    return PROJECT_ICON_ALL.filter((name) => normalizeSearchText(`${name} ${projectIconLabel(name)}`).includes(q));
  }

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
      icon: normalizeProjectIcon(raw.icon),
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
    heart: '<path d="M12 20s-7.5-4.6-9.3-9C1.3 7.7 3 4.5 6.2 4.5c2 0 3.5 1.1 4.3 2.4a.6.6 0 0 0 1 0c.8-1.3 2.3-2.4 4.3-2.4 3.2 0 4.9 3.2 3.6 6.5-1.8 4.4-9.4 9-9.4 9z"/>',
    book: '<path d="M4 5.5a2 2 0 0 1 2-2h5.5v17H6a2 2 0 0 1-2-2z"/><path d="M20 5.5a2 2 0 0 0-2-2h-5.5v17H18a2 2 0 0 0 2-2z"/>',
    gamepad: '<rect x="2.5" y="8.5" width="19" height="9.5" rx="4"/><path d="M7 11v4M5 13h4"/><circle cx="16" cy="12" r="0.9"/><circle cx="18.5" cy="14.5" r="0.9"/>',
    camera: '<rect x="3" y="7" width="18" height="13" rx="2.5"/><path d="M8 7l1.5-2.5h5L16 7"/><circle cx="12" cy="13.5" r="3.5"/>',
    music: '<path d="M9 18V5.5l10-2v12.5"/><circle cx="7" cy="18.5" r="2.5"/><circle cx="17" cy="16" r="2.5"/>',
    palette: '<path d="M12 3.5a8.5 8.5 0 1 0 0 17c1 0 1.5-.6 1.5-1.4 0-.4-.2-.7-.4-1-.2-.3-.4-.6-.4-1 0-.8.7-1.4 1.5-1.4H16a4.5 4.5 0 0 0 4.5-4.5c0-4.2-3.8-7.7-8.5-7.7z"/><circle cx="7.5" cy="12" r="1"/><circle cx="9" cy="8.5" r="1"/><circle cx="13" cy="7.5" r="1"/><circle cx="16.5" cy="10" r="1"/>',
    plane: '<path d="M3 11.5L20.5 4 13 20.5l-2-7.5z"/><path d="M11 13.5L20.5 4"/>',
    leaf: '<path d="M19 5c-7 0-13 4.5-14.5 11.5a1 1 0 0 0 1 1.2C13 17 18 12 19 5z"/><path d="M6 18c2-5 6-9 11-11.5"/>',
};

  function icon(name, className = '') {
    const paths = ICON_PATHS[name] || ICON_PATHS.box;
    return `<svg class="i ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${paths}</svg>`;
  }

  /* Ícones de projeto: vetorizados do Lucide (https://lucide.dev, ISC license)
   * e embutidos aqui como paths estáticos — sem dependência externa nem
   * chamada de rede, igual ao restante do app. */
  const PROJECT_ICON_PATHS = {
    Activity: '<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/>',
    AlarmClock: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2"/><path d="M5 3 2 6"/><path d="m22 6-3-3"/><path d="M6.38 18.7 4 21"/><path d="M17.64 18.67 20 21"/>',
    AlertTriangle: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    Ambulance: '<path d="M10 10H6"/><path d="M14 18V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v11a1 1 0 0 0 1 1h2"/><path d="M19 18h2a1 1 0 0 0 1-1v-3.28a1 1 0 0 0-.684-.948l-1.923-.641a1 1 0 0 1-.578-.502l-1.539-3.076A1 1 0 0 0 16.382 8H14"/><path d="M8 8v4"/><path d="M9 18h6"/><circle cx="17" cy="18" r="2"/><circle cx="7" cy="18" r="2"/>',
    Anchor: '<path d="M12 6v16"/><path d="m19 13 2-1a9 9 0 0 1-18 0l2 1"/><path d="M9 11h6"/><circle cx="12" cy="4" r="2"/>',
    Antenna: '<path d="M2 12 7 2"/><path d="m7 12 5-10"/><path d="m12 12 5-10"/><path d="m17 12 5-10"/><path d="M4.5 7h15"/><path d="M12 16v6"/>',
    Apple: '<path d="M12 6.528V3a1 1 0 0 1 1-1h0"/><path d="M18.237 21A15 15 0 0 0 22 11a6 6 0 0 0-10-4.472A6 6 0 0 0 2 11a15.1 15.1 0 0 0 3.763 10 3 3 0 0 0 3.648.648 5.5 5.5 0 0 1 5.178 0A3 3 0 0 0 18.237 21"/>',
    Archive: '<rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/>',
    AtSign: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"/>',
    Atom: '<circle cx="12" cy="12" r="1"/><path d="M20.2 20.2c2.04-2.03.02-7.36-4.5-11.9-4.54-4.52-9.87-6.54-11.9-4.5-2.04 2.03-.02 7.36 4.5 11.9 4.54 4.52 9.87 6.54 11.9 4.5Z"/><path d="M15.7 15.7c4.52-4.54 6.54-9.87 4.5-11.9-2.03-2.04-7.36-.02-11.9 4.5-4.52 4.54-6.54 9.87-4.5 11.9 2.03 2.04 7.36.02 11.9-4.5Z"/>',
    Award: '<path d="m15.477 12.89 1.515 8.526a.5.5 0 0 1-.81.47l-3.58-2.687a1 1 0 0 0-1.197 0l-3.586 2.686a.5.5 0 0 1-.81-.469l1.514-8.526"/><circle cx="12" cy="8" r="6"/>',
    Baby: '<path d="M10 16c.5.3 1.2.5 2 .5s1.5-.2 2-.5"/><path d="M15 12h.01"/><path d="M19.38 6.813A9 9 0 0 1 20.8 10.2a2 2 0 0 1 0 3.6 9 9 0 0 1-17.6 0 2 2 0 0 1 0-3.6A9 9 0 0 1 12 3c2 0 3.5 1.1 3.5 2.5s-.9 2.5-2 2.5c-.8 0-1.5-.4-1.5-1"/><path d="M9 12h.01"/>',
    Backpack: '<path d="M4 10a4 4 0 0 1 4-4h8a4 4 0 0 1 4 4v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/><path d="M8 10h8"/><path d="M8 18h8"/><path d="M8 22v-6a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>',
    BadgeCheck: '<path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><path d="m16 9-5.5 5.5L8 12"/>',
    Banknote: '<rect width="20" height="12" x="2" y="6" rx="2"/><circle cx="12" cy="12" r="2"/><path d="M6 12h.01M18 12h.01"/>',
    BarChart3: '<path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/>',
    Barcode: '<path d="M3 5v14"/><path d="M8 5v14"/><path d="M12 5v14"/><path d="M17 5v14"/><path d="M21 5v14"/>',
    Battery: '<path d="M 22 14 L 22 10"/><rect x="2" y="6" width="16" height="12" rx="2"/>',
    BatteryCharging: '<path d="m11 7-3 5h4l-3 5"/><path d="M14.856 6H16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2.935"/><path d="M22 14v-4"/><path d="M5.14 18H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h2.936"/>',
    Bed: '<path d="M2 4v16"/><path d="M2 8h18a2 2 0 0 1 2 2v10"/><path d="M2 17h20"/><path d="M6 8v9"/>',
    Beer: '<path d="M17 11h1a3 3 0 0 1 0 6h-1"/><path d="M9 12v6"/><path d="M13 12v6"/><path d="M14 7.5c-1 0-1.44.5-3 .5s-2-.5-3-.5-1.72.5-2.5.5a2.5 2.5 0 0 1 0-5c.78 0 1.57.5 2.5.5S9.44 2 11 2s2 1.5 3 1.5 1.72-.5 2.5-.5a2.5 2.5 0 0 1 0 5c-.78 0-1.5-.5-2.5-.5Z"/><path d="M5 8v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V8"/>',
    Bell: '<path d="M10.268 21a2 2 0 0 0 3.464 0"/><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326"/>',
    Bike: '<circle cx="18.5" cy="17.5" r="3.5"/><circle cx="5.5" cy="17.5" r="3.5"/><circle cx="15" cy="5" r="1"/><path d="M12 17.5V14l-3-3 4-3 2 3h2"/>',
    Binary: '<rect x="14" y="14" width="4" height="6" rx="2"/><rect x="6" y="4" width="4" height="6" rx="2"/><path d="M6 20h4"/><path d="M14 10h4"/><path d="M6 14h2v6"/><path d="M14 4h2v6"/>',
    Bluetooth: '<path d="m7 7 10 10-5 5V2l5 5L7 17"/>',
    Book: '<path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H19a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20"/>',
    BookOpen: '<path d="M12 5v16"/><path d="M20.001 19A2 2 0 0022 17V5a2 2 0 00-1.999-2L16 3.002A5 5 0 0012 5a5 5 0 00-4-2H4a2 2 0 00-2 2v12a2 2 0 001.999 2H8a5 5 0 014 2 5 5 0 014-2z"/>',
    Bookmark: '<path d="M17 3a2 2 0 0 1 2 2v15a1 1 0 0 1-1.496.868l-4.512-2.578a2 2 0 0 0-1.984 0l-4.512 2.578A1 1 0 0 1 5 20V5a2 2 0 0 1 2-2z"/>',
    Bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
    Box: '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
    Boxes: '<path d="M2.97 12.92A2 2 0 0 0 2 14.63v3.24a2 2 0 0 0 .97 1.71l3 1.8a2 2 0 0 0 2.06 0L12 19v-5.5l-5-3-4.03 2.42Z"/><path d="m7 16.5-4.74-2.85"/><path d="m7 16.5 5-3"/><path d="M7 16.5v5.17"/><path d="M12 13.5V19l3.97 2.38a2 2 0 0 0 2.06 0l3-1.8a2 2 0 0 0 .97-1.71v-3.24a2 2 0 0 0-.97-1.71L17 10.5l-5 3Z"/><path d="m17 16.5-5-3"/><path d="m17 16.5 4.74-2.85"/><path d="M17 16.5v5.17"/><path d="M7.97 4.42A2 2 0 0 0 7 6.13v4.37l5 3 5-3V6.13a2 2 0 0 0-.97-1.71l-3-1.8a2 2 0 0 0-2.06 0l-3 1.8Z"/><path d="M12 8 7.26 5.15"/><path d="m12 8 4.74-2.85"/><path d="M12 13.5V8"/>',
    Braces: '<path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1"/><path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1"/>',
    Brain: '<path d="M12 18V5"/><path d="M15 13a4.17 4.17 0 0 1-3-4 4.17 4.17 0 0 1-3 4"/><path d="M17.598 6.5A3 3 0 1 0 12 5a3 3 0 1 0-5.598 1.5"/><path d="M17.997 5.125a4 4 0 0 1 2.526 5.77"/><path d="M18 18a4 4 0 0 0 2-7.464"/><path d="M19.967 17.483A4 4 0 1 1 12 18a4 4 0 1 1-7.967-.517"/><path d="M6 18a4 4 0 0 1-2-7.464"/><path d="M6.003 5.125a4 4 0 0 0-2.526 5.77"/>',
    Briefcase: '<path d="M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/><rect width="20" height="14" x="2" y="6" rx="2"/>',
    Bug: '<path d="M12 20v-9"/><path d="M14 7a4 4 0 0 1 4 4v3a6 6 0 0 1-12 0v-3a4 4 0 0 1 4-4z"/><path d="M14.12 3.88 16 2"/><path d="M21 21a4 4 0 0 0-3.81-4"/><path d="M21 5a4 4 0 0 1-3.55 3.97"/><path d="M22 13h-4"/><path d="M3 21a4 4 0 0 1 3.81-4"/><path d="M3 5a4 4 0 0 0 3.55 3.97"/><path d="M6 13H2"/><path d="m8 2 1.88 1.88"/><path d="M9 7.13V6a3 3 0 1 1 6 0v1.13"/>',
    Building: '<path d="M12 10h.01"/><path d="M12 14h.01"/><path d="M12 6h.01"/><path d="M16 10h.01"/><path d="M16 14h.01"/><path d="M16 6h.01"/><path d="M8 10h.01"/><path d="M8 14h.01"/><path d="M8 6h.01"/><path d="M9 22v-3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3"/><rect x="4" y="2" width="16" height="20" rx="2"/>',
    Building2: '<path d="M10 12h4"/><path d="M10 8h4"/><path d="M14 21v-3a2 2 0 0 0-4 0v3"/><path d="M6 10H4a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-2"/><path d="M6 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16"/>',
    Bus: '<path d="M8 6v6"/><path d="M15 6v6"/><path d="M2 12h19.6"/><path d="M18 18h3s.5-1.7.8-2.8c.1-.4.2-.8.2-1.2 0-.4-.1-.8-.2-1.2l-1.4-5C20.1 6.8 19.1 6 18 6H4a2 2 0 0 0-2 2v10h3"/><circle cx="7" cy="18" r="2"/><path d="M9 18h5"/><circle cx="16" cy="18" r="2"/>',
    Cake: '<path d="M20 21v-8a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8"/><path d="M4 16s.5-1 2-1 2.5 2 4 2 2.5-2 4-2 2.5 2 4 2 2-1 2-1"/><path d="M2 21h20"/><path d="M7 8v3"/><path d="M12 8v3"/><path d="M17 8v3"/><path d="M7 4h.01"/><path d="M12 4h.01"/><path d="M17 4h.01"/>',
    Calculator: '<rect width="16" height="20" x="4" y="2" rx="2"/><line x1="8" x2="16" y1="6" y2="6"/><line x1="16" x2="16" y1="14" y2="18"/><path d="M16 10h.01"/><path d="M12 10h.01"/><path d="M8 10h.01"/><path d="M12 14h.01"/><path d="M8 14h.01"/><path d="M12 18h.01"/><path d="M8 18h.01"/>',
    Calendar: '<path d="M8 2v3"/><path d="M16 2v3"/><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/>',
    CalendarCheck: '<path d="M8 2v3"/><path d="M16 2v3"/><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="m9 15 2 2 4-4"/>',
    CalendarClock: '<path d="M16 14v2.2l1.6 1"/><path d="M16 2v3"/><path d="M21 7.338V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2h2.338"/><path d="M3 9h5.859"/><path d="M8 2v3"/><circle cx="16" cy="16" r="6"/>',
    CalendarDays: '<path d="M8 2v3"/><path d="M16 2v3"/><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/><path d="M8 13h.01"/><path d="M12 13h.01"/><path d="M16 13h.01"/><path d="M8 17h.01"/><path d="M12 17h.01"/><path d="M16 17h.01"/>',
    Camera: '<path d="M13.997 4a2 2 0 0 1 1.76 1.05l.486.9A2 2 0 0 0 18.003 7H20a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h1.997a2 2 0 0 0 1.759-1.048l.489-.904A2 2 0 0 1 10.004 4z"/><circle cx="12" cy="13" r="3"/>',
    Car: '<path d="M19 17h2c.6 0 1-.4 1-1v-3c0-.9-.7-1.7-1.5-1.9C18.7 10.6 16 10 16 10s-1.3-1.4-2.2-2.3c-.5-.4-1.1-.7-1.8-.7H5c-.6 0-1.1.4-1.4.9l-1.4 2.9A3.7 3.7 0 0 0 2 12v4c0 .6.4 1 1 1h2"/><circle cx="7" cy="17" r="2"/><path d="M9 17h6"/><circle cx="17" cy="17" r="2"/>',
    CheckSquare: '<path d="M21 10.656V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h12.344"/><path d="m9 11 3 3L22 4"/>',
    ChefHat: '<path d="M17 21a1 1 0 0 0 1-1v-5.35c0-.457.316-.844.727-1.041a4 4 0 0 0-2.134-7.589 5 5 0 0 0-9.186 0 4 4 0 0 0-2.134 7.588c.411.198.727.585.727 1.041V20a1 1 0 0 0 1 1Z"/><path d="M6 17h12"/>',
    Cherry: '<path d="M2 17a5 5 0 0 0 10 0c0-2.76-2.5-5-5-3-2.5-2-5 .24-5 3Z"/><path d="M12 17a5 5 0 0 0 10 0c0-2.76-2.5-5-5-3-2.5-2-5 .24-5 3Z"/><path d="M7 14c3.22-2.91 4.29-8.75 5-12 1.66 2.38 4.94 9 5 12"/><path d="M22 9c-4.29 0-7.14-2.33-10-7 5.71 0 10 4.67 10 7Z"/>',
    CircleDollarSign: '<circle cx="12" cy="12" r="10"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 18V6"/>',
    Clapperboard: '<path d="m12.296 3.464 3.02 3.956"/><path d="M20.2 6 3 11l-.9-2.4c-.3-1.1.3-2.2 1.3-2.5l13.5-4c1.1-.3 2.2.3 2.5 1.3z"/><path d="M3 11h18v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="m6.18 5.276 3.1 3.899"/>',
    ClipboardCheck: '<rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 14 2 2 4-4"/>',
    ClipboardList: '<rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/>',
    Clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    Clock3: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6h4"/>',
    Cloud: '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
    CloudCog: '<path d="m10.852 19.772-.383.924"/><path d="m13.148 14.228.383-.923"/><path d="M13.148 19.772a3 3 0 1 0-2.296-5.544l-.383-.923"/><path d="m13.53 20.696-.382-.924a3 3 0 1 1-2.296-5.544"/><path d="m14.772 15.852.923-.383"/><path d="m14.772 18.148.923.383"/><path d="M4.2 15.1a7 7 0 1 1 9.93-9.858A7 7 0 0 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.2"/><path d="m9.228 15.852-.923-.383"/><path d="m9.228 18.148-.923.383"/>',
    CloudLightning: '<path d="M6 16.326A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 .5 8.973"/><path d="m13 12-3 5h4l-3 5"/>',
    CloudRain: '<path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M16 14v6"/><path d="M8 14v6"/><path d="M12 16v6"/>',
    CloudSnow: '<path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M8 15h.01"/><path d="M8 19h.01"/><path d="M12 17h.01"/><path d="M12 21h.01"/><path d="M16 15h.01"/><path d="M16 19h.01"/>',
    Code: '<path d="m16 18 6-6-6-6"/><path d="m8 6-6 6 6 6"/>',
    Code2: '<path d="m18 16 4-4-4-4"/><path d="m6 8-4 4 4 4"/><path d="m14.5 4-5 16"/>',
    Coffee: '<path d="M10 2v2"/><path d="M14 2v2"/><path d="M16 8a1 1 0 0 1 1 1v8a4 4 0 0 1-4 4H7a4 4 0 0 1-4-4V9a1 1 0 0 1 1-1h14a4 4 0 1 1 0 8h-1"/><path d="M6 2v2"/>',
    Cog: '<path d="M11 10.27 7 3.34"/><path d="m11 13.73-4 6.93"/><path d="M12 22v-2"/><path d="M12 2v2"/><path d="M14 12h8"/><path d="m17 20.66-1-1.73"/><path d="m17 3.34-1 1.73"/><path d="M2 12h2"/><path d="m20.66 17-1.73-1"/><path d="m20.66 7-1.73 1"/><path d="m3.34 17 1.73-1"/><path d="m3.34 7 1.73 1"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="12" r="8"/>',
    Coins: '<path d="M13.744 17.736a6 6 0 1 1-7.48-7.48"/><path d="M15 6h1v4"/><path d="m6.134 14.768.866-.5 2 3.464"/><circle cx="16" cy="8" r="6"/>',
    Compass: '<circle cx="12" cy="12" r="10"/><path d="m16.24 7.76-1.804 5.411a2 2 0 0 1-1.265 1.265L7.76 16.24l1.804-5.411a2 2 0 0 1 1.265-1.265z"/>',
    Cpu: '<path d="M12 20v2"/><path d="M12 2v2"/><path d="M17 20v2"/><path d="M17 2v2"/><path d="M2 12h2"/><path d="M2 17h2"/><path d="M2 7h2"/><path d="M20 12h2"/><path d="M20 17h2"/><path d="M20 7h2"/><path d="M7 20v2"/><path d="M7 2v2"/><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="8" y="8" width="8" height="8" rx="1"/>',
    CreditCard: '<rect width="20" height="14" x="2" y="5" rx="2"/><line x1="2" x2="22" y1="10" y2="10"/><path d="M6 14h2"/>',
    Crown: '<path d="M11.562 3.266a.5.5 0 0 1 .876 0L15.39 8.87a1 1 0 0 0 1.516.294L21.183 5.5a.5.5 0 0 1 .798.519l-2.834 10.246a1 1 0 0 1-.956.734H5.81a1 1 0 0 1-.957-.734L2.02 6.02a.5.5 0 0 1 .798-.519l4.276 3.664a1 1 0 0 0 1.516-.294z"/><path d="M5 21h14"/>',
    Database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/>',
    Dice5: '<rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><path d="M16 8h.01"/><path d="M8 8h.01"/><path d="M8 16h.01"/><path d="M16 16h.01"/><path d="M12 12h.01"/>',
    DollarSign: '<line x1="12" x2="12" y1="2" y2="22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
    DoorOpen: '<path d="M10 21H2"/><path d="M10 3H7a2 2 0 00-2 2v16"/><path d="M14 12h.01"/><path d="M19 21V5a2 2 0 00-1.675-1.974l-6.163-1.013A1 1 0 0010 3v18a1 1 0 001.124.992z"/><path d="M22 21h-3"/>',
    Drill: '<path d="M10 18a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H5a3 3 0 0 1-3-3 1 1 0 0 1 1-1z"/><path d="M13 10H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1l-.81 3.242a1 1 0 0 1-.97.758H8"/><path d="M14 4h3a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-3"/><path d="M18 6h4"/><path d="m5 10-2 8"/><path d="m7 18 2-8"/>',
    Droplet: '<path d="M12 22a7 7 0 0 0 7-7c0-2-1-3.9-3-5.5s-3.5-4-4-6.5c-.5 2.5-2 4.9-4 6.5C6 11.1 5 13 5 15a7 7 0 0 0 7 7z"/>',
    Droplets: '<path d="M7 16.3c2.2 0 4-1.83 4-4.05 0-1.16-.57-2.26-1.71-3.19S7.29 6.75 7 5.3c-.29 1.45-1.14 2.84-2.29 3.76S3 11.1 3 12.25c0 2.22 1.8 4.05 4 4.05z"/><path d="M12.56 6.6A10.97 10.97 0 0 0 14 3.02c.5 2.5 2 4.9 4 6.5s3 3.5 3 5.5a6.98 6.98 0 0 1-11.91 4.97"/>',
    Dumbbell: '<path d="M17.596 12.768a2 2 0 1 0 2.829-2.829l-1.768-1.767a2 2 0 0 0 2.828-2.829l-2.828-2.828a2 2 0 0 0-2.829 2.828l-1.767-1.768a2 2 0 1 0-2.829 2.829z"/><path d="m2.5 21.5 1.4-1.4"/><path d="m20.1 3.9 1.4-1.4"/><path d="M5.343 21.485a2 2 0 1 0 2.829-2.828l1.767 1.768a2 2 0 1 0 2.829-2.829l-6.364-6.364a2 2 0 1 0-2.829 2.829l1.768 1.767a2 2 0 0 0-2.828 2.829z"/><path d="m9.6 14.4 4.8-4.8"/>',
    Eye: '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>',
    EyeOff: '<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/><path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/><path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/><path d="m2 2 20 20"/>',
    Factory: '<path d="M12 16h.01"/><path d="M16 16h.01"/><path d="M3 19a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V8.5a.5.5 0 0 0-.769-.422l-4.462 2.844A.5.5 0 0 1 15 10.5v-2a.5.5 0 0 0-.769-.422L9.77 10.922A.5.5 0 0 1 9 10.5V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2z"/><path d="M8 16h.01"/>',
    FileBox: '<path d="M14 2v5a1 1 0 001 1h5"/><path d="M14.692 22H18a2 2 0 002-2V8a2.4 2.4 0 00-.706-1.706l-3.588-3.588A2.4 2.4 0 0014 2H6a2 2 0 00-2 2v3.804"/><path d="M2.264 13.752 7 16.5l4.737-2.748"/><path d="M2.995 13.014A2 2 0 002 14.744v3.516a2 2 0 00.996 1.73l3 1.74a2 2 0 002.008 0l3-1.74A2 2 0 0012 18.26v-3.517a2 2 0 00-.995-1.73l-3-1.742a2 2 0 00-1.892-.064z"/><path d="M7 16.5V22"/>',
    FileCode: '<path d="M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"/><path d="M14 2v5a1 1 0 0 0 1 1h5"/><path d="M10 12.5 8 15l2 2.5"/><path d="m14 12.5 2 2.5-2 2.5"/>',
    FileSignature: '<path d="M14.364 13.634a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506l4.013-4.009a1 1 0 0 0-3.004-3.004z"/><path d="M14.487 7.858A1 1 0 0 1 14 7V2"/><path d="M20 19.645V20a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l2.516 2.516"/><path d="M8 18h1"/>',
    FileText: '<path d="M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"/><path d="M14 2v5a1 1 0 0 0 1 1h5"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/>',
    Files: '<path d="M15 2h-4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V8"/><path d="M16.706 2.706A2.4 2.4 0 0 0 15 2v5a1 1 0 0 0 1 1h5a2.4 2.4 0 0 0-.706-1.706z"/><path d="M5 7a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h8a2 2 0 0 0 1.732-1"/>',
    Film: '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M7 3v18"/><path d="M3 7.5h4"/><path d="M3 12h18"/><path d="M3 16.5h4"/><path d="M17 3v18"/><path d="M17 7.5h4"/><path d="M17 16.5h4"/>',
    Fingerprint: '<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>',
    Flag: '<path d="M4 22V4a1 1 0 0 1 .4-.8A6 6 0 0 1 8 2c3 0 5 2 7.333 2q2 0 3.067-.8A1 1 0 0 1 20 4v10a1 1 0 0 1-.4.8A6 6 0 0 1 16 16c-3 0-5-2-8-2a6 6 0 0 0-4 1.528"/>',
    Flame: '<path d="M12 3q1 4 4 6.5t3 5.5a1 1 0 0 1-14 0 5 5 0 0 1 1-3 1 1 0 0 0 5 0c0-2-1.5-3-1.5-5q0-2 2.5-4"/>',
    FlaskConical: '<path d="M14 2v6a2 2 0 0 0 .245.96l5.51 10.08A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.08A2 2 0 0 0 10 8V2"/><path d="M6.453 15h11.094"/><path d="M8.5 2h7"/>',
    Flower: '<circle cx="12" cy="12" r="3"/><path d="M12 16.5A4.5 4.5 0 1 1 7.5 12 4.5 4.5 0 1 1 12 7.5a4.5 4.5 0 1 1 4.5 4.5 4.5 4.5 0 1 1-4.5 4.5"/><path d="M12 7.5V9"/><path d="M7.5 12H9"/><path d="M16.5 12H15"/><path d="M12 16.5V15"/><path d="m8 8 1.88 1.88"/><path d="M14.12 9.88 16 8"/><path d="m8 16 1.88-1.88"/><path d="M14.12 14.12 16 16"/>',
    Flower2: '<path d="M12 5a3 3 0 1 1 3 3m-3-3a3 3 0 1 0-3 3m3-3v1M9 8a3 3 0 1 0 3 3M9 8h1m5 0a3 3 0 1 1-3 3m3-3h-1m-2 3v-1"/><circle cx="12" cy="8" r="2"/><path d="M12 10v12"/><path d="M12 22c4.2 0 7-1.667 7-5-4.2 0-7 1.667-7 5Z"/><path d="M12 22c-4.2 0-7-1.667-7-5 4.2 0 7 1.667 7 5Z"/>',
    Folder: '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
    FolderKanban: '<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/><path d="M8 10v4"/><path d="M12 10v2"/><path d="M16 10v6"/>',
    FolderOpen: '<path d="m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"/>',
    Footprints: '<path d="M4 16v-2.38C4 11.5 2.97 10.5 3 8c.03-2.72 1.49-6 4.5-6C9.37 2 10 3.8 10 5.5c0 3.11-2 5.66-2 8.68V16a2 2 0 1 1-4 0Z"/><path d="M20 20v-2.38c0-2.12 1.03-3.12 1-5.62-.03-2.72-1.49-6-4.5-6C14.63 6 14 7.8 14 9.5c0 3.11 2 5.66 2 8.68V20a2 2 0 1 0 4 0Z"/><path d="M16 17h4"/><path d="M4 13h4"/>',
    Fuel: '<path d="M14 13h2a2 2 0 0 1 2 2v2a2 2 0 0 0 4 0v-6.998a2 2 0 0 0-.59-1.42L18 5"/><path d="M14 21V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v16"/><path d="M2 21h13"/><path d="M3 9h11"/>',
    Gamepad2: '<line x1="6" x2="10" y1="11" y2="11"/><line x1="8" x2="8" y1="9" y2="13"/><line x1="15" x2="15.01" y1="12" y2="12"/><line x1="18" x2="18.01" y1="10" y2="10"/><path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258-.007-.05-.011-.1-.017-.151A4 4 0 0 0 17.32 5z"/>',
    Gavel: '<path d="m14 13-8.381 8.38a1 1 0 0 1-3.001-3l8.384-8.381"/><path d="m16 16 6-6"/><path d="m21.5 10.5-8-8"/><path d="m8 8 6-6"/><path d="m8.5 7.5 8 8"/>',
    Gem: '<path d="M10.5 3 8 9l4 13 4-13-2.5-6"/><path d="M17 3a2 2 0 0 1 1.6.8l3 4a2 2 0 0 1 .013 2.382l-7.99 10.986a2 2 0 0 1-3.247 0l-7.99-10.986A2 2 0 0 1 2.4 7.8l2.998-3.997A2 2 0 0 1 7 3z"/><path d="M2 9h20"/>',
    Gift: '<path d="M12 7v14"/><path d="M20 11v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8"/><path d="M7.5 7a1 1 0 0 1 0-5A4.8 8 0 0 1 12 7a4.8 8 0 0 1 4.5-5 1 1 0 0 1 0 5"/><rect x="3" y="7" width="18" height="4" rx="1"/>',
    GitBranch: '<path d="M15 6a9 9 0 0 0-9 9V3"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/>',
    GitCommit: '<circle cx="12" cy="12" r="3"/><line x1="3" x2="9" y1="12" y2="12"/><line x1="15" x2="21" y1="12" y2="12"/>',
    GitMerge: '<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M6 21V9a9 9 0 0 0 9 9"/>',
    GitPullRequest: '<circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" x2="6" y1="9" y2="21"/>',
    Glasses: '<circle cx="6" cy="15" r="4"/><circle cx="18" cy="15" r="4"/><path d="M14 15a2 2 0 0 0-2-2 2 2 0 0 0-2 2"/><path d="M2.5 13 5 7c.7-1.3 1.4-2 3-2"/><path d="M21.5 13 19 7c-.7-1.3-1.5-2-3-2"/>',
    Globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    GraduationCap: '<path d="M21.42 10.922a1 1 0 0 0-.019-1.838L12.83 5.18a2 2 0 0 0-1.66 0L2.6 9.08a1 1 0 0 0 0 1.832l8.57 3.908a2 2 0 0 0 1.66 0z"/><path d="M22 10v6"/><path d="M6 12.5V16a6 3 0 0 0 12 0v-3.5"/>',
    Grid3x3: '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M3 9h18"/><path d="M3 15h18"/><path d="M9 3v18"/><path d="M15 3v18"/>',
    Guitar: '<path d="m11.9 12.1 4.514-4.514"/><path d="M20.1 2.3a1 1 0 0 0-1.4 0l-1.114 1.114A2 2 0 0 0 17 4.828v1.344a2 2 0 0 1-.586 1.414A2 2 0 0 1 17.828 7h1.344a2 2 0 0 0 1.414-.586L21.7 5.3a1 1 0 0 0 0-1.4z"/><path d="m6 16 2 2"/><path d="M8.23 9.85A3 3 0 0 1 11 8a5 5 0 0 1 5 5 3 3 0 0 1-1.85 2.77l-.92.38A2 2 0 0 0 12 18a4 4 0 0 1-4 4 6 6 0 0 1-6-6 4 4 0 0 1 4-4 2 2 0 0 0 1.85-1.23z"/>',
    Hammer: '<path d="m15 12-9.373 9.373a1 1 0 0 1-3.001-3L12 9"/><path d="m18 15 4-4"/><path d="m21.5 11.5-1.914-1.914A2 2 0 0 1 19 8.172v-.344a2 2 0 0 0-.586-1.414l-1.657-1.657A6 6 0 0 0 12.516 3H9l1.243 1.243A6 6 0 0 1 12 8.485V10l2 2h1.172a2 2 0 0 1 1.414.586L18.5 14.5"/>',
    Handshake: '<path d="m11 17 2 2a1 1 0 1 0 3-3"/><path d="m14 14 2.5 2.5a1 1 0 1 0 3-3l-3.88-3.88a3 3 0 0 0-4.24 0l-.88.88a1 1 0 1 1-3-3l2.81-2.81a5.79 5.79 0 0 1 7.06-.87l.47.28a2 2 0 0 0 1.42.25L21 4"/><path d="m21 3 1 11h-2"/><path d="M3 3 2 14l6.5 6.5a1 1 0 1 0 3-3"/><path d="M3 4h8"/>',
    HardDrive: '<path d="M10 16h.01"/><path d="M2.212 11.577a2 2 0 0 0-.212.896V18a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-5.527a2 2 0 0 0-.212-.896L18.55 5.11A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M21.946 12.013H2.054"/><path d="M6 16h.01"/>',
    Headphones: '<path d="M3 14h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a9 9 0 0 1 18 0v7a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3"/>',
    Heart: '<path d="M2 9.5a5.5 5.5 0 0 1 9.591-3.676.56.56 0 0 0 .818 0A5.49 5.49 0 0 1 22 9.5c0 2.29-1.5 4-3 5.5l-5.492 5.313a2 2 0 0 1-3 .019L5 15c-1.5-1.5-3-3.2-3-5.5"/>',
    HeartHandshake: '<path d="M19.414 14.414C21 12.828 22 11.5 22 9.5a5.5 5.5 0 0 0-9.591-3.676.6.6 0 0 1-.818.001A5.5 5.5 0 0 0 2 9.5c0 2.3 1.5 4 3 5.5l5.535 5.362a2 2 0 0 0 2.879.052 2.12 2.12 0 0 0-.004-3 2.124 2.124 0 1 0 3-3 2.124 2.124 0 0 0 3.004 0 2 2 0 0 0 0-2.828l-1.881-1.882a2.41 2.41 0 0 0-3.409 0l-1.71 1.71a2 2 0 0 1-2.828 0 2 2 0 0 1 0-2.828l2.823-2.762"/>',
    HeartPulse: '<path d="M2 9.5a5.5 5.5 0 0 1 9.591-3.676.56.56 0 0 0 .818 0A5.49 5.49 0 0 1 22 9.5c0 2.29-1.5 4-3 5.5l-5.492 5.313a2 2 0 0 1-3 .019L5 15c-1.5-1.5-3-3.2-3-5.5"/><path d="M3.22 13H9.5l.5-1 2 4.5 2-7 1.5 3.5h5.27"/>',
    HelpCircle: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
    Home: '<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    Hospital: '<path d="M12 7v4"/><path d="M14 21v-3a2 2 0 0 0-4 0v3"/><path d="M14 9h-4"/><path d="M18 11h2a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2h2"/><path d="M18 21V5a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16"/>',
    Hourglass: '<path d="M5 22h14"/><path d="M5 2h14"/><path d="M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22"/><path d="M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2"/>',
    House: '<path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    IceCream: '<path d="m7 11 4.08 10.35a1 1 0 0 0 1.84 0L17 11"/><path d="M17 7A5 5 0 0 0 7 7"/><path d="M17 7a2 2 0 0 1 0 4H7a2 2 0 0 1 0-4"/>',
    Image: '<rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>',
    Inbox: '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    Info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    Kanban: '<path d="M5 3v14"/><path d="M12 3v8"/><path d="M19 3v18"/>',
    Key: '<path d="m2 21 9.6-9.6"/><path d="m7.5 15.5 2.3 2.3a1 1 0 0 1 0 1.4l-2.1 2.1a1 1 0 0 1-1.4 0L4 19"/><circle cx="15.5" cy="7.5" r="5.5"/>',
    KeyRound: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    Keyboard: '<path d="M10 8h.01"/><path d="M12 12h.01"/><path d="M14 8h.01"/><path d="M16 12h.01"/><path d="M18 8h.01"/><path d="M6 8h.01"/><path d="M7 16h10"/><path d="M8 12h.01"/><rect width="20" height="16" x="2" y="4" rx="2"/>',
    Lamp: '<path d="M12 12v6"/><path d="M4.077 10.615A1 1 0 0 0 5 12h14a1 1 0 0 0 .923-1.385l-3.077-7.384A2 2 0 0 0 15 2H9a2 2 0 0 0-1.846 1.23Z"/><path d="M8 20a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v1a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1z"/>',
    Landmark: '<path d="M10 18v-7"/><path d="M11.119 2.205a2 2 0 0 1 1.762 0l7.84 3.846A.5.5 0 0 1 20.5 7h-17a.5.5 0 0 1-.22-.949z"/><path d="M14 18v-7"/><path d="M18 18v-7"/><path d="M3 22h18"/><path d="M6 18v-7"/>',
    Laptop: '<path d="M18 5a2 2 0 0 1 2 2v8.526a2 2 0 0 0 .212.897l1.068 2.127a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45l1.068-2.127A2 2 0 0 0 4 15.526V7a2 2 0 0 1 2-2z"/><path d="M20.054 15.987H3.946"/>',
    Layers: '<path d="M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z"/><path d="M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12"/><path d="M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17"/>',
    LayoutDashboard: '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
    LayoutGrid: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    Leaf: '<path d="M11 20a10 10 0 0010-10 25.9 25.9 0 00-1.04-7.281 1 1 0 00-1.755-.325C15.833 5.5 13 5.5 9.8 6.1A7 7 0 0011 20"/><path d="M2 21a5 5 0 012.911-4.544C7.613 15.212 8.351 15.24 11 13"/>',
    Library: '<path d="m16 6 4 14"/><path d="M12 6v14"/><path d="M8 8v12"/><path d="M4 4v16"/>',
    Lightbulb: '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/>',
    LineChart: '<path d="M3 3v16a2 2 0 0 0 2 2h16"/><path d="m19 9-5 5-4-4-3 3"/>',
    ListTodo: '<path d="M13 5h8"/><path d="M13 12h8"/><path d="M13 19h8"/><path d="m3 17 2 2 4-4"/><rect x="3" y="4" width="6" height="6" rx="1"/>',
    Lock: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    Luggage: '<path d="M6 20a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2"/><path d="M8 18V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v14"/><path d="M10 20h4"/><circle cx="16" cy="20" r="2"/><circle cx="8" cy="20" r="2"/>',
    Mail: '<path d="m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7"/><rect x="2" y="4" width="20" height="16" rx="2"/>',
    Map: '<path d="M14.106 5.553a2 2 0 0 0 1.788 0l3.659-1.83A1 1 0 0 1 21 4.619v12.764a1 1 0 0 1-.553.894l-4.553 2.277a2 2 0 0 1-1.788 0l-4.212-2.106a2 2 0 0 0-1.788 0l-3.659 1.83A1 1 0 0 1 3 19.381V6.618a1 1 0 0 1 .553-.894l4.553-2.277a2 2 0 0 1 1.788 0z"/><path d="M15 5.764v15"/><path d="M9 3.236v15"/>',
    MapPin: '<path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0"/><circle cx="12" cy="10" r="3"/>',
    MapPinned: '<path d="M18 8c0 3.613-3.869 7.429-5.393 8.795a1 1 0 01-1.214 0C9.87 15.429 6 11.613 6 8a6 6 0 0112 0"/><path d="M4.474 15h-.197a1 1 0 00-.969.753l-1.097 4.35a1.5 1.5 0 001.444 1.898L20.344 22a1.5 1.5 0 001.446-1.897l-1.098-4.35a1 1 0 00-.969-.753h-.197"/><circle cx="12" cy="8" r="2"/>',
    Medal: '<path d="M7.21 15 2.66 7.14a2 2 0 0 1 .13-2.2L4.4 2.8A2 2 0 0 1 6 2h12a2 2 0 0 1 1.6.8l1.6 2.14a2 2 0 0 1 .14 2.2L16.79 15"/><path d="M11 12 5.12 2.2"/><path d="m13 12 5.88-9.8"/><path d="M8 7h8"/><circle cx="12" cy="17" r="5"/><path d="M12 18v-2h-.5"/>',
    Megaphone: '<path d="M11 6a13 13 0 0 0 8.4-2.8A1 1 0 0 1 21 4v12a1 1 0 0 1-1.6.8A13 13 0 0 0 11 14H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2z"/><path d="M6 14a12 12 0 0 0 2.4 7.2 2 2 0 0 0 3.2-2.4A8 8 0 0 1 10 14"/><path d="M8 6v8"/>',
    MessageCircle: '<path d="M2.992 16.342a2 2 0 0 1 .094 1.167l-1.065 3.29a1 1 0 0 0 1.236 1.168l3.413-.998a2 2 0 0 1 1.099.092 10 10 0 1 0-4.777-4.719"/>',
    MessageSquare: '<path d="M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z"/>',
    Mic: '<path d="M12 19v3"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><rect x="9" y="2" width="6" height="13" rx="3"/>',
    Microscope: '<path d="M6 18h8"/><path d="M3 22h18"/><path d="M14 22a7 7 0 1 0 0-14h-1"/><path d="M9 14h2"/><path d="M9 12a2 2 0 0 1-2-2V6h6v4a2 2 0 0 1-2 2Z"/><path d="M12 6V3a1 1 0 0 0-1-1H9a1 1 0 0 0-1 1v3"/>',
    Milestone: '<path d="M12 13v8"/><path d="M12 3v3"/><path d="M18.172 6a2 2 0 0 1 1.414.586l2.06 2.06a1.207 1.207 0 0 1 0 1.708l-2.06 2.06a2 2 0 0 1-1.414.586H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1z"/>',
    Monitor: '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
    Moon: '<path d="M20.985 12.486a9 9 0 1 1-9.473-9.472c.405-.022.617.46.402.803a6 6 0 0 0 8.268 8.268c.344-.215.825-.004.803.401"/>',
    Mountain: '<path d="m8 3 4 8 5-5 5 15H2L8 3z"/>',
    Music: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    Music2: '<circle cx="8" cy="18" r="4"/><path d="M12 18V2l7 4"/>',
    Navigation: '<polygon points="3 11 22 2 13 21 11 13 3 11"/>',
    Network: '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
    Notebook: '<path d="M2 6h4"/><path d="M2 10h4"/><path d="M2 14h4"/><path d="M2 18h4"/><rect width="16" height="20" x="4" y="2" rx="2"/><path d="M16 2v20"/>',
    Package: '<path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z"/><path d="M12 22V12"/><polyline points="3.29 7 12 12 20.71 7"/><path d="m7.5 4.27 9 5.15"/>',
    PackageCheck: '<path d="M12 22V12"/><path d="m16 17 2 2 4-4"/><path d="M21 11.127V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.729l7 4a2 2 0 0 0 2 .001l1.32-.753"/><path d="M3.29 7 12 12l8.71-5"/><path d="m7.5 4.27 8.997 5.148"/>',
    PackageOpen: '<path d="M12 22v-9"/><path d="M15.17 2.21a1.67 1.67 0 0 1 1.63 0L21 4.57a1.93 1.93 0 0 1 0 3.36L8.82 14.79a1.655 1.655 0 0 1-1.64 0L3 12.43a1.93 1.93 0 0 1 0-3.36z"/><path d="M20 13v3.87a2.06 2.06 0 0 1-1.11 1.83l-6 3.08a1.93 1.93 0 0 1-1.78 0l-6-3.08A2.06 2.06 0 0 1 4 16.87V13"/><path d="M21 12.43a1.93 1.93 0 0 0 0-3.36L8.83 2.2a1.64 1.64 0 0 0-1.63 0L3 4.57a1.93 1.93 0 0 0 0 3.36l12.18 6.86a1.636 1.636 0 0 0 1.63 0z"/>',
    Paintbrush: '<path d="m14.622 17.897-10.68-2.913"/><path d="M18.376 2.622a1 1 0 1 1 3.002 3.002L17.36 9.643a.5.5 0 0 0 0 .707l.944.944a2.41 2.41 0 0 1 0 3.408l-.944.944a.5.5 0 0 1-.707 0L8.354 7.348a.5.5 0 0 1 0-.707l.944-.944a2.41 2.41 0 0 1 3.408 0l.944.944a.5.5 0 0 0 .707 0z"/><path d="M9 8c-1.804 2.71-3.97 3.46-6.583 3.948a.507.507 0 0 0-.302.819l7.32 8.883a1 1 0 0 0 1.185.204C12.735 20.405 16 16.792 16 15"/>',
    Paintbrush2: '<path d="M10 2v2"/><path d="M14 2v4"/><path d="M17 2a1 1 0 0 1 1 1v9H6V3a1 1 0 0 1 1-1z"/><path d="M6 12a1 1 0 0 0-1 1v1a2 2 0 0 0 2 2h2a1 1 0 0 1 1 1v2.9a2 2 0 1 0 4 0V17a1 1 0 0 1 1-1h2a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1"/>',
    Palette: '<path d="M12 22a1 1 0 0 1 0-20 10 9 0 0 1 10 9 5 5 0 0 1-5 5h-2.25a1.75 1.75 0 0 0-1.4 2.8l.3.4a1.75 1.75 0 0 1-1.4 2.8z"/><circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/>',
    Palmtree: '<path d="M13 8c0-2.76-2.46-5-5.5-5S2 5.24 2 8h2l1-1 1 1h4"/><path d="M13 7.14A5.82 5.82 0 0 1 16.5 6c3.04 0 5.5 2.24 5.5 5h-3l-1-1-1 1h-3"/><path d="M5.89 9.71c-2.15 2.15-2.3 5.47-.35 7.43l4.24-4.25.7-.7.71-.71 2.12-2.12c-1.95-1.96-5.27-1.8-7.42.35"/><path d="M11 15.5c.5 2.5-.17 4.5-1 6.5h4c2-5.5-.5-12-1-14"/>',
    Paperclip: '<path d="m16 6-8.414 8.586a2 2 0 0 0 2.829 2.829l8.414-8.586a4 4 0 1 0-5.657-5.657l-8.379 8.551a6 6 0 1 0 8.485 8.485l8.379-8.551"/>',
    ParkingCircle: '<circle cx="12" cy="12" r="10"/><path d="M9 17V7h4a3 3 0 0 1 0 6H9"/>',
    ParkingSquare: '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 17V7h4a3 3 0 0 1 0 6H9"/>',
    PartyPopper: '<path d="M5.8 11.3 2 22l10.7-3.79"/><path d="M4 3h.01"/><path d="M22 8h.01"/><path d="M15 2h.01"/><path d="M22 20h.01"/><path d="m22 2-2.24.75a2.9 2.9 0 0 0-1.96 3.12c.1.86-.57 1.63-1.45 1.63h-.38c-.86 0-1.6.6-1.76 1.44L14 10"/><path d="m22 13-.82-.33c-.86-.34-1.82.2-1.98 1.11c-.11.7-.72 1.22-1.43 1.22H17"/><path d="m11 2 .33.82c.34.86-.2 1.82-1.11 1.98C9.52 4.9 9 5.52 9 6.23V7"/><path d="M11 13c1.93 1.93 2.83 4.17 2 5-.83.83-3.07-.07-5-2-1.93-1.93-2.83-4.17-2-5 .83-.83 3.07.07 5 2Z"/>',
    PencilRuler: '<path d="M13 7 8.7 2.7a2.41 2.41 0 0 0-3.4 0L2.7 5.3a2.41 2.41 0 0 0 0 3.4L7 13"/><path d="m8 6 2-2"/><path d="m18 16 2-2"/><path d="m17 11 4.3 4.3c.94.94.94 2.46 0 3.4l-2.6 2.6c-.94.94-2.46.94-3.4 0L11 17"/><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>',
    Percent: '<line x1="19" x2="5" y1="5" y2="19"/><circle cx="6.5" cy="6.5" r="2.5"/><circle cx="17.5" cy="17.5" r="2.5"/>',
    Phone: '<path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>',
    PhoneCall: '<path d="M13 2a9 9 0 0 1 9 9"/><path d="M13 6a5 5 0 0 1 5 5"/><path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>',
    PieChart: '<path d="M21 12c.552 0 1.005-.449.95-.998a10 10 0 0 0-8.953-8.951c-.55-.055-.998.398-.998.95v8a1 1 0 0 0 1 1z"/><path d="M21.21 15.89A10 10 0 1 1 8 2.83"/>',
    PiggyBank: '<path d="M11 17h3v2a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1v-3a3.16 3.16 0 0 0 2-2h1a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1h-1a5 5 0 0 0-2-4V3a4 4 0 0 0-3.2 1.6l-.3.4H11a6 6 0 0 0-6 6v1a5 5 0 0 0 2 4v3a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1z"/><path d="M16 10h.01"/><path d="M2 8v1a2 2 0 0 0 2 2h1"/>',
    Pill: '<path d="m10.5 20.5 10-10a4.95 4.95 0 1 0-7-7l-10 10a4.95 4.95 0 1 0 7 7Z"/><path d="m8.5 8.5 7 7"/>',
    Pin: '<path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/>',
    Pizza: '<path d="m12 14-1 1"/><path d="m13.75 18.25-1.25 1.42"/><path d="M17.775 5.654a15.68 15.68 0 0 0-12.121 12.12"/><path d="M18.8 9.3a1 1 0 0 0 2.1 7.7"/><path d="M21.964 20.732a1 1 0 0 1-1.232 1.232l-18-5a1 1 0 0 1-.695-1.232A19.68 19.68 0 0 1 15.732 2.037a1 1 0 0 1 1.232.695z"/>',
    Plane: '<path d="M17.8 19.2 16 11l3.5-3.5C21 6 21.5 4 21 3c-1-.5-3 0-4.5 1.5L13 8 4.8 6.2c-.5-.1-.9.1-1.1.5l-.3.5c-.2.5-.1 1 .3 1.3L9 12l-2 3H4l-1 1 3 2 2 3 1-1v-3l3-2 3.5 5.3c.3.4.8.5 1.3.3l.5-.2c.4-.3.6-.7.5-1.2z"/>',
    PlaneTakeoff: '<path d="M2 22h20"/><path d="M6.36 17.4 4 17l-2-4 1.1-.55a2 2 0 0 1 1.8 0l.17.1a2 2 0 0 0 1.8 0L8 12 5 6l.9-.45a2 2 0 0 1 2.09.2l4.02 3a2 2 0 0 0 2.1.2l4.19-2.06a2.41 2.41 0 0 1 1.73-.17L21 7a1.4 1.4 0 0 1 .87 1.99l-.38.76c-.23.46-.6.84-1.07 1.08L7.58 17.2a2 2 0 0 1-1.22.18Z"/>',
    Plug: '<path d="M12 22v-5"/><path d="M15 8V2"/><path d="M17 8a1 1 0 0 1 1 1v4a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V9a1 1 0 0 1 1-1z"/><path d="M9 8V2"/>',
    Presentation: '<path d="M2 3h20"/><path d="M21 3v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V3"/><path d="m7 21 5-5 5 5"/>',
    Printer: '<path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 9V3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v6"/><rect x="6" y="14" width="12" height="8" rx="1"/>',
    Puzzle: '<path d="M15.39 4.39a1 1 0 0 0 1.68-.474 2.5 2.5 0 1 1 3.014 3.015 1 1 0 0 0-.474 1.68l1.683 1.682a2.414 2.414 0 0 1 0 3.414L19.61 15.39a1 1 0 0 1-1.68-.474 2.5 2.5 0 1 0-3.014 3.015 1 1 0 0 1 .474 1.68l-1.683 1.682a2.414 2.414 0 0 1-3.414 0L8.61 19.61a1 1 0 0 0-1.68.474 2.5 2.5 0 1 1-3.014-3.015 1 1 0 0 0 .474-1.68l-1.683-1.682a2.414 2.414 0 0 1 0-3.414L4.39 8.61a1 1 0 0 1 1.68.474 2.5 2.5 0 1 0 3.014-3.015 1 1 0 0 1-.474-1.68l1.683-1.682a2.414 2.414 0 0 1 3.414 0z"/>',
    QrCode: '<rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>',
    Radio: '<path d="M16.247 7.761a6 6 0 0 1 0 8.478"/><path d="M19.075 4.933a10 10 0 0 1 0 14.134"/><path d="M4.925 19.067a10 10 0 0 1 0-14.134"/><path d="M7.753 16.239a6 6 0 0 1 0-8.478"/><circle cx="12" cy="12" r="2"/>',
    Rainbow: '<path d="M22 17a10 10 0 0 0-20 0"/><path d="M6 17a6 6 0 0 1 12 0"/><path d="M10 17a2 2 0 0 1 4 0"/>',
    Receipt: '<path d="M12 17V7"/><path d="M16 8h-6a2 2 0 0 0 0 4h4a2 2 0 0 1 0 4H8"/><path d="M4 3a1 1 0 0 1 1-1 1.3 1.3 0 0 1 .7.2l.933.6a1.3 1.3 0 0 0 1.4 0l.934-.6a1.3 1.3 0 0 1 1.4 0l.933.6a1.3 1.3 0 0 0 1.4 0l.933-.6a1.3 1.3 0 0 1 1.4 0l.934.6a1.3 1.3 0 0 0 1.4 0l.933-.6A1.3 1.3 0 0 1 19 2a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1 1.3 1.3 0 0 1-.7-.2l-.933-.6a1.3 1.3 0 0 0-1.4 0l-.934.6a1.3 1.3 0 0 1-1.4 0l-.933-.6a1.3 1.3 0 0 0-1.4 0l-.933.6a1.3 1.3 0 0 1-1.4 0l-.934-.6a1.3 1.3 0 0 0-1.4 0l-.933.6a1.3 1.3 0 0 1-.7.2 1 1 0 0 1-1-1z"/>',
    Refrigerator: '<path d="M5 6a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6Z"/><path d="M5 10h14"/><path d="M15 7v6"/>',
    Rocket: '<path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09"/><path d="M9 12a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.4 22.4 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 .05 5 .05"/>',
    Router: '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6"/><path d="M10.01 18H10"/><path d="M15 10v4"/><path d="M17.84 7.17a4 4 0 0 0-5.66 0"/><path d="M20.66 4.34a8 8 0 0 0-11.31 0"/>',
    Rss: '<path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/>',
    Ruler: '<path d="M21.3 15.3a2.4 2.4 0 0 1 0 3.4l-2.6 2.6a2.4 2.4 0 0 1-3.4 0L2.7 8.7a2.41 2.41 0 0 1 0-3.4l2.6-2.6a2.41 2.41 0 0 1 3.4 0Z"/><path d="m14.5 12.5 2-2"/><path d="m11.5 9.5 2-2"/><path d="m8.5 6.5 2-2"/><path d="m17.5 15.5 2-2"/>',
    Salad: '<path d="M19.496 12a2.5 2.5 0 00.399-2.214A2 2 0 0020.32 6.5 2 2 0 0019 3a2 2 0 00-1.5.68 2 2 0 00-3.287.424 2.5 2.5 0 00-3.189 2.06A3 3 0 0012 12l4-4"/><path d="M4 12a1 1 0 00-.99 1.133A9 9 0 0012 21a9 9 0 008.99-7.867A1 1 0 0020 12z"/><path d="M7 21h10"/><path d="M9.85 6.907A3.5 3.5 0 005.05 12"/>',
    Sandwich: '<path d="m2.37 11.223 8.372-6.777a2 2 0 0 1 2.516 0l8.371 6.777"/><path d="M21 15a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1h-5.25"/><path d="M3 15a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h9"/><path d="m6.67 15 6.13 4.6a2 2 0 0 0 2.8-.4l3.15-4.2"/><rect width="20" height="4" x="2" y="11" rx="1"/>',
    Satellite: '<path d="m13.5 6.5-3.148-3.148a1.205 1.205 0 0 0-1.704 0L6.352 5.648a1.205 1.205 0 0 0 0 1.704L9.5 10.5"/><path d="M16.5 7.5 19 5"/><path d="m17.5 10.5 3.148 3.148a1.205 1.205 0 0 1 0 1.704l-2.296 2.296a1.205 1.205 0 0 1-1.704 0L13.5 14.5"/><path d="M9 21a6 6 0 0 0-6-6"/><path d="M9.352 10.648a1.205 1.205 0 0 0 0 1.704l2.296 2.296a1.205 1.205 0 0 0 1.704 0l4.296-4.296a1.205 1.205 0 0 0 0-1.704l-2.296-2.296a1.205 1.205 0 0 0-1.704 0z"/>',
    Scale: '<path d="M12 3v18"/><path d="m19 8 3 8a5 5 0 0 1-6 0zV7"/><path d="M3 7h1a17 17 0 0 0 8-2 17 17 0 0 0 8 2h1"/><path d="m5 8 3 8a5 5 0 0 1-6 0zV7"/><path d="M7 21h10"/>',
    Scan: '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>',
    ScanFace: '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><path d="M9 9h.01"/><path d="M15 9h.01"/>',
    School: '<path d="M14 21v-3a2 2 0 0 0-4 0v3"/><path d="M18 4.933V21"/><path d="m4 6 7.106-3.79a2 2 0 0 1 1.788 0L20 6"/><path d="m6 11-3.52 2.147a1 1 0 0 0-.48.854V19a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-5a1 1 0 0 0-.48-.853L18 11"/><path d="M6 4.933V21"/><circle cx="12" cy="9" r="2"/>',
    Scissors: '<circle cx="6" cy="6" r="3"/><path d="M8.12 8.12 12 12"/><path d="M20 4 8.12 15.88"/><circle cx="6" cy="18" r="3"/><path d="M14.8 14.8 20 20"/>',
    Send: '<path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z"/><path d="m21.854 2.147-10.94 10.939"/>',
    Server: '<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>',
    Settings: '<path d="M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"/><circle cx="12" cy="12" r="3"/>',
    Shapes: '<path d="M8.3 10a.7.7 0 0 1-.626-1.079L11.4 3a.7.7 0 0 1 1.198-.043L16.3 8.9a.7.7 0 0 1-.572 1.1Z"/><rect x="3" y="14" width="7" height="7" rx="1"/><circle cx="17.5" cy="17.5" r="3.5"/>',
    Share2: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" x2="15.42" y1="13.51" y2="17.49"/><line x1="15.41" x2="8.59" y1="6.51" y2="10.49"/>',
    Shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    ShieldAlert: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    ShieldCheck: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    Ship: '<path d="M12 2v2"/><path d="M12 9.189V13"/><path d="M19 12V6a2 2 0 00-2-2H7a2 2 0 00-2 2v6"/><path d="M19.38 19A11.6 11.6 0 0021 13l-8.188-3.639a2 2 0 00-1.624 0L3 13.001a11.6 11.6 0 002.81 7.76"/><path d="M2 20c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1s1.2 1 2.5 1c2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/>',
    Shirt: '<path d="M20.38 3.46 16 2a4 4 0 0 1-8 0L3.62 3.46a2 2 0 0 0-1.34 2.23l.58 3.47a1 1 0 0 0 .99.84H6v10c0 1.1.9 2 2 2h8a2 2 0 0 0 2-2V10h2.15a1 1 0 0 0 .99-.84l.58-3.47a2 2 0 0 0-1.34-2.23z"/>',
    ShoppingBag: '<path d="M16 10a4 4 0 0 1-8 0"/><path d="M3.103 6.034h17.794"/><path d="M3.4 5.467a2 2 0 0 0-.4 1.2V20a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6.667a2 2 0 0 0-.4-1.2l-2-2.667A2 2 0 0 0 17 2H7a2 2 0 0 0-1.6.8z"/>',
    ShoppingCart: '<path d="m2.05 2.05 1.099-.028a1 1 0 0 1 1.008.815l2.69 14.347A1 1 0 0 0 7.83 18H18"/><path d="M4.563 5h16.435a1 1 0 0 1 .981 1.204l-1.026 6.226A2 2 0 0 1 18.962 14H6.25"/><circle cx="18" cy="20" r="2"/><circle cx="8" cy="20" r="2"/>',
    Signal: '<path d="M2 20h.01"/><path d="M7 20v-4"/><path d="M12 20v-8"/><path d="M17 20V8"/><path d="M22 4v16"/>',
    Signpost: '<path d="M12 13v8"/><path d="M12 3v3"/><path d="M2.354 10.354a1.207 1.207 0 0 1 0-1.708l2.06-2.06A2 2 0 0 1 5.828 6h12.344a2 2 0 0 1 1.414.586l2.06 2.06a1.207 1.207 0 0 1 0 1.708l-2.06 2.06a2 2 0 0 1-1.414.586H5.828a2 2 0 0 1-1.414-.586z"/>',
    SlidersHorizontal: '<path d="M10 5H3"/><path d="M12 19H3"/><path d="M14 3v4"/><path d="M16 17v4"/><path d="M21 12h-9"/><path d="M21 19h-5"/><path d="M21 5h-7"/><path d="M8 10v4"/><path d="M8 12H3"/>',
    Smartphone: '<rect width="14" height="20" x="5" y="2" rx="2" ry="2"/><path d="M12 18h.01"/>',
    Smile: '<path d="M15 10V9"/><path d="M16.472 15a6 6 0 01-8.943 0"/><path d="M9 10V9"/><circle cx="12" cy="12" r="10"/>',
    Snowflake: '<path d="m10 20-1.25-2.5L6 18"/><path d="M10 4 8.75 6.5 6 6"/><path d="m14 20 1.25-2.5L18 18"/><path d="m14 4 1.25 2.5L18 6"/><path d="m17 21-3-6h-4"/><path d="m17 3-3 6 1.5 3"/><path d="M2 12h6.5L10 9"/><path d="m20 10-1.5 2 1.5 2"/><path d="M22 12h-6.5L14 15"/><path d="m4 10 1.5 2L4 14"/><path d="m7 21 3-6-1.5-3"/><path d="m7 3 3 6h4"/>',
    Sofa: '<path d="M20 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v3"/><path d="M2 16a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-5a2 2 0 0 0-4 0v1.5a.5.5 0 0 1-.5.5h-11a.5.5 0 0 1-.5-.5V11a2 2 0 0 0-4 0z"/><path d="M4 18v2"/><path d="M20 18v2"/><path d="M12 4v9"/>',
    Soup: '<path d="M11.248 3c.273.1.808.53.747 1.36-.05.83-.938 1.2-.989 2.02-.06.78.333 1.24.727 1.62"/><path d="M16.252 3c.268.1.794.53.745 1.36-.06.83-.923 1.2-.993 2.02-.05.78.338 1.24.725 1.62"/><path d="M19.5 12 22 6"/><path d="M4 12a1 1 0 00-.99 1.133A9 9 0 0012 21a9 9 0 008.99-7.867A1 1 0 0020 12z"/><path d="M6.252 3c.268.1.794.53.745 1.36-.06.83-.923 1.2-.993 2.02-.05.78.338 1.24.735 1.62"/><path d="M7 21h10"/>',
    Sparkles: '<path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z"/><path d="M20 2v4"/><path d="M22 4h-4"/><circle cx="4" cy="20" r="2"/>',
    SprayCan: '<path d="M3 3h.01"/><path d="M7 5h.01"/><path d="M11 7h.01"/><path d="M3 7h.01"/><path d="M7 9h.01"/><path d="M3 11h.01"/><rect width="4" height="4" x="15" y="5"/><path d="m19 9 2 2v10c0 .6-.4 1-1 1h-6c-.6 0-1-.4-1-1V11l2-2"/><path d="m13 14 8-2"/><path d="m13 19 8-2"/>',
    Sprout: '<path d="M14 9.536V7a4 4 0 0 1 4-4h1.5a.5.5 0 0 1 .5.5V5a4 4 0 0 1-4 4 4 4 0 0 0-4 4c0 2 1 3 1 5a5 5 0 0 1-1 3"/><path d="M4 9a5 5 0 0 1 8 4 5 5 0 0 1-8-4"/><path d="M5 21h14"/>',
    Star: '<path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/>',
    Stethoscope: '<path d="M11 2v2"/><path d="M5 2v2"/><path d="M5 3H4a2 2 0 0 0-2 2v4a6 6 0 0 0 12 0V5a2 2 0 0 0-2-2h-1"/><path d="M8 15a6 6 0 0 0 12 0v-3"/><circle cx="20" cy="10" r="2"/>',
    Sticker: '<path d="M21 9a2.4 2.4 0 0 0-.706-1.706l-3.588-3.588A2.4 2.4 0 0 0 15 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2z"/><path d="M15 3v5a1 1 0 0 0 1 1h5"/><path d="M8 13h.01"/><path d="M16 13h.01"/><path d="M10 16s.8 1 2 1c1.3 0 2-1 2-1"/>',
    Store: '<path d="M15 21v-5a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v5"/><path d="M17.774 10.31a1.12 1.12 0 0 0-1.549 0 2.5 2.5 0 0 1-3.451 0 1.12 1.12 0 0 0-1.548 0 2.5 2.5 0 0 1-3.452 0 1.12 1.12 0 0 0-1.549 0 2.5 2.5 0 0 1-3.77-3.248l2.889-4.184A2 2 0 0 1 7 2h10a2 2 0 0 1 1.653.873l2.895 4.192a2.5 2.5 0 0 1-3.774 3.244"/><path d="M4 10.95V19a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8.05"/>',
    Sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    Sunrise: '<path d="M12 2v8"/><path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/><path d="M22 22H2"/><path d="m8 6 4-4 4 4"/><path d="M16 18a4 4 0 0 0-8 0"/>',
    Sunset: '<path d="M12 10V2"/><path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/><path d="M22 22H2"/><path d="m16 6-4 4-4-4"/><path d="M16 18a4 4 0 0 0-8 0"/>',
    Syringe: '<path d="m18 2 4 4"/><path d="m17 7 3-3"/><path d="M19 9 8.7 19.3c-1 1-2.5 1-3.4 0l-.6-.6c-1-1-1-2.5 0-3.4L15 5"/><path d="m9 11 4 4"/><path d="m5 19-3 3"/><path d="m14 4 6 6"/>',
    Tag: '<path d="M12.586 2.586A2 2 0 0 0 11.172 2H4a2 2 0 0 0-2 2v7.172a2 2 0 0 0 .586 1.414l8.704 8.704a2.426 2.426 0 0 0 3.42 0l6.58-6.58a2.426 2.426 0 0 0 0-3.42z"/><circle cx="7.5" cy="7.5" r=".5" fill="currentColor"/>',
    Tags: '<path d="M13.172 2a2 2 0 0 1 1.414.586l6.71 6.71a2.4 2.4 0 0 1 0 3.408l-4.592 4.592a2.4 2.4 0 0 1-3.408 0l-6.71-6.71A2 2 0 0 1 6 9.172V3a1 1 0 0 1 1-1z"/><path d="M2 7v6.172a2 2 0 0 0 .586 1.414l6.71 6.71a2.4 2.4 0 0 0 3.191.193"/><circle cx="10.5" cy="6.5" r=".5" fill="currentColor"/>',
    Target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    Tent: '<path d="M3.5 21 14 3"/><path d="M20.5 21 10 3"/><path d="M15.5 21 12 15l-3.5 6"/><path d="M2 21h20"/>',
    Terminal: '<path d="M12 19h8"/><path d="m4 17 6-6-6-6"/>',
    Thermometer: '<path d="M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z"/>',
    ThumbsUp: '<path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2a3.13 3.13 0 0 1 3 3.88Z"/><path d="M7 10v12"/>',
    Timer: '<line x1="10" x2="14" y1="2" y2="2"/><line x1="12" x2="15" y1="14" y2="11"/><circle cx="12" cy="14" r="8"/>',
    Toothbrush: '<path d="M15 11c-2 2-4 2-6 4l-7 7"/><path d="m22 4-7.414 7.414-2-2A2 2 0 0114 6c0-.512.196-1.024.586-1.414A2 2 0 0116 4a2 2 0 013.262-1.552l2.152 2.138"/>',
    TrafficCone: '<path d="M16.05 10.966a5 2.5 0 0 1-8.1 0"/><path d="m16.923 14.049 4.48 2.04a1 1 0 0 1 .001 1.831l-8.574 3.9a2 2 0 0 1-1.66 0l-8.574-3.91a1 1 0 0 1 0-1.83l4.484-2.04"/><path d="M16.949 14.14a5 2.5 0 1 1-9.9 0L10.063 3.5a2 2 0 0 1 3.874 0z"/><path d="M9.194 6.57a5 2.5 0 0 0 5.61 0"/>',
    Train: '<rect width="16" height="16" x="4" y="3" rx="2"/><path d="M4 11h16"/><path d="M12 3v8"/><path d="m8 19-2 3"/><path d="m18 22-2-3"/><path d="M8 15h.01"/><path d="M16 15h.01"/>',
    Trees: '<path d="M10 10v.2A3 3 0 0 1 8.9 16H5a3 3 0 0 1-1-5.8V10a3 3 0 0 1 6 0Z"/><path d="M7 16v6"/><path d="M13 19v3"/><path d="M12 19h8.3a1 1 0 0 0 .7-1.7L18 14h.3a1 1 0 0 0 .7-1.7L16 9h.2a1 1 0 0 0 .8-1.7L13 3l-1.4 1.5"/>',
    TrendingUp: '<path d="M16 7h6v6"/><path d="m22 7-8.5 8.5-5-5L2 17"/>',
    Trophy: '<path d="M10 14.66V17a1 1 0 0 1-1 1 2 2 0 0 0-2 2v2"/><path d="M14 14.66V17a1 1 0 0 0 1 1 2 2 0 0 1 2 2v2"/><path d="M17.916 10H19.5A2.5 2.5 0 0 0 22 7.5V5a1 1 0 0 0-1-1h-3"/><path d="M4 22h16"/><path d="M6 9a6 6 0 0 0 12 0V3a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1z"/><path d="M6.084 10H4.5A2.5 2.5 0 0 1 2 7.5V5a1 1 0 0 1 1-1h3"/>',
    Truck: '<path d="M14 18V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v11a1 1 0 0 0 1 1h2"/><path d="M15 18H9"/><path d="M19 18h2a1 1 0 0 0 1-1v-3.65a1 1 0 0 0-.22-.624l-3.48-4.35A1 1 0 0 0 17.52 8H14"/><circle cx="17" cy="18" r="2"/><circle cx="7" cy="18" r="2"/>',
    Tv: '<path d="m17 2-5 5-5-5"/><rect width="20" height="15" x="2" y="7" rx="2"/>',
    Umbrella: '<path d="M12 13v7a2 2 0 0 0 4 0"/><path d="M12 2v2"/><path d="M20.992 13a1 1 0 0 0 .97-1.274 10.284 10.284 0 0 0-19.923 0A1 1 0 0 0 3 13z"/>',
    Unlock: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    Usb: '<circle cx="10" cy="7" r="1"/><circle cx="4" cy="20" r="1"/><path d="M4.7 19.3 19 5"/><path d="m21 3-3 1 2 2Z"/><path d="M9.26 7.68 5 12l2 5"/><path d="m10 14 5 2 3.5-3.5"/><path d="m18 12 1-1 1 1-1 1Z"/>',
    User: '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    UserCheck: '<path d="m16 11 2 2 4-4"/><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>',
    UserCircle: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="10" r="3"/><path d="M7 20.662V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.662"/>',
    UserPlus: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" x2="19" y1="8" y2="14"/><line x1="22" x2="16" y1="11" y2="11"/>',
    Users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><path d="M16 3.128a4 4 0 0 1 0 7.744"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><circle cx="9" cy="7" r="4"/>',
    Utensils: '<path d="M3 2v7c0 1.1.9 2 2 2h4a2 2 0 0 0 2-2V2"/><path d="M7 2v20"/><path d="M21 15V2a5 5 0 0 0-5 5v6c0 1.1.9 2 2 2h3Zm0 0v7"/>',
    UtensilsCrossed: '<path d="m16 2-2.3 2.3a3 3 0 0 0 0 4.2l1.8 1.8a3 3 0 0 0 4.2 0L22 8"/><path d="M15 15 3.3 3.3a4.2 4.2 0 0 0 0 6l7.3 7.3c.7.7 2 .7 2.8 0L15 15Zm0 0 7 7"/><path d="m2.1 21.8 6.4-6.3"/><path d="m19 5-7 7"/>',
    Wallet: '<path d="M19 7V4a1 1 0 0 0-1-1H5a2 2 0 0 0 0 4h15a1 1 0 0 1 1 1v4h-3a2 2 0 0 0 0 4h3a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1"/><path d="M3 5v14a2 2 0 0 0 2 2h15a1 1 0 0 0 1-1v-4"/>',
    Warehouse: '<path d="M18 21V10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1v11"/><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 1.132-1.803l7.95-3.974a2 2 0 0 1 1.837 0l7.948 3.974A2 2 0 0 1 22 8z"/><path d="M6 13h12"/><path d="M6 17h12"/>',
    WashingMachine: '<path d="M3 6h3"/><path d="M17 6h.01"/><rect width="18" height="20" x="3" y="2" rx="2"/><circle cx="12" cy="13" r="5"/><path d="M12 18a2.5 2.5 0 0 0 0-5 2.5 2.5 0 0 1 0-5"/>',
    Watch: '<path d="M12 10v2.2l1.6 1"/><path d="m16.13 7.66-.81-4.05a2 2 0 0 0-2-1.61h-2.68a2 2 0 0 0-2 1.61l-.78 4.05"/><path d="m7.88 16.36.8 4a2 2 0 0 0 2 1.61h2.72a2 2 0 0 0 2-1.61l.81-4.05"/><circle cx="12" cy="12" r="6"/>',
    Waves: '<path d="M2 12q2.5 2 5 0t5 0 5 0 5 0"/><path d="M2 19q2.5 2 5 0t5 0 5 0 5 0"/><path d="M2 5q2.5 2 5 0t5 0 5 0 5 0"/>',
    Webhook: '<path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/>',
    Wifi: '<path d="M12 20h.01"/><path d="M2 8.82a15 15 0 0 1 20 0"/><path d="M5 12.859a10 10 0 0 1 14 0"/><path d="M8.5 16.429a5 5 0 0 1 7 0"/>',
    Wind: '<path d="M12.8 19.6A2 2 0 1 0 14 16H2"/><path d="M17.5 8a2.5 2.5 0 1 1 2 4H2"/><path d="M9.8 4.4A2 2 0 1 1 11 8H2"/>',
    Wine: '<path d="M8 22h8"/><path d="M7 10h10"/><path d="M12 15v7"/><path d="M12 15a5 5 0 0 0 5-5c0-2-.5-4-2-8H9c-1.5 4-2 6-2 8a5 5 0 0 0 5 5Z"/>',
    Workflow: '<rect width="8" height="8" x="3" y="3" rx="2"/><path d="M7 11v4a2 2 0 0 0 2 2h4"/><rect width="8" height="8" x="13" y="13" rx="2"/>',
    Wrench: '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.106-3.105c.32-.322.863-.22.983.218a6 6 0 0 1-8.259 7.057l-7.91 7.91a1 1 0 0 1-2.999-3l7.91-7.91a6 6 0 0 1 7.057-8.259c.438.12.54.662.219.984z"/>',
    Zap: '<path d="M15.914 4a1.5 1.5 0 00-2.474-1.561l-9 9A1.5 1.5 0 005.5 14h4.002a.5.5 0 01.471.666L8.086 20a1.5 1.5 0 002.475 1.56l9-9A1.5 1.5 0 0018.5 10h-3.997a.5.5 0 01-.472-.667z"/>',
  };

  function projectIcon(name, className = '') {
    const markup = PROJECT_ICON_PATHS[name] || ICON_PATHS.folder;
    return `<svg class="i ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${markup}</svg>`;
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
        <span class="project-icon pc-${color}">${isNone ? icon('box') : projectIcon(project.icon)}</span>
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
      <span class="project-icon project-icon-lg pc-${project.color}">${projectIcon(project.icon)}</span>
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

  function createProjectRecord({ name, description = '', color = 'blue', iconName = DEFAULT_PROJECT_ICON }) {
    const ts = nowIso();
    return {
      id: newId(),
      name: name.slice(0, LIMITS.projectName),
      description: description.slice(0, LIMITS.projectDesc),
      color: PROJECT_COLOR_IDS.includes(color) ? color : 'blue',
      icon: normalizeProjectIcon(iconName),
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

  function iconGridButtonsHTML(names, selected) {
    if (!names.length) return `<p class="icon-picker-empty">Nenhum ícone encontrado.</p>`;
    return names.map((name) => {
      const label = projectIconLabel(name);
      const isSelected = name === selected;
      return `<button type="button" class="icon-choice${isSelected ? ' is-selected' : ''}" data-icon-pick="${esc(name)}" role="radio" aria-checked="${isSelected}" title="${esc(label)}">
        <span class="icon-choice-body">${projectIcon(name)}</span><span class="sr-only">${esc(label)}</span>
      </button>`;
    }).join('');
  }

  function iconPickerHTML(selected) {
    const extra = PROJECT_ICON_ALL.length - PROJECT_ICON_COMMON.length;
    return `<div class="icon-picker" data-icon-picker>
      <input type="hidden" name="icon" value="${esc(selected)}">
      <div class="icon-choices" role="radiogroup" aria-label="Ícone" data-icon-grid>${iconGridButtonsHTML(PROJECT_ICON_COMMON, selected)}</div>
      <p class="icon-picker-hint" data-icon-hint>+${extra} ícones disponíveis — use a busca para encontrar outros.</p>
      <div class="search icon-search" role="search">
        <span class="search-icon">${icon('search')}</span>
        <input type="search" class="search-input" data-icon-search placeholder="Buscar ícone (ex.: casa, viagem, dinheiro…)" aria-label="Buscar ícone" autocomplete="off" spellcheck="false">
      </div>
    </div>`;
  }

  function openProjectForm(projectId = null) {
    const existing = projectId ? findProject(projectId) : null;
    if (projectId && !existing) return;
    const isEdit = !!existing;
    const data = existing || { name: '', description: '', color: PROJECT_COLOR_IDS[(state.vault.projects.length + 1) % PROJECT_COLOR_IDS.length], icon: DEFAULT_PROJECT_ICON };
    const body = `<form id="project-form" class="form" novalidate autocomplete="off">
      <div class="project-preview" id="p-preview">
        <span class="project-icon project-icon-lg" data-preview-icon></span>
        <div><span class="project-name" data-preview-name></span><span class="project-desc" data-preview-desc></span></div>
      </div>
      ${fieldHTML({ id: 'p-name', label: 'Nome do projeto', required: true, control: `<input type="text" id="p-name" name="name" class="input" maxlength="${LIMITS.projectName}" placeholder="Ex.: Cliente Alfa, Infra interna…" aria-describedby="p-name-error" data-autofocus>` })}
      ${fieldHTML({ id: 'p-desc', label: 'Descrição (opcional)', control: `<textarea id="p-desc" name="description" class="input textarea" rows="3" maxlength="${LIMITS.projectDesc}" placeholder="Para que serve este projeto?"></textarea>` })}
      <div class="field"><span class="label">Cor</span>${colorSwatchesHTML('color', data.color)}</div>
      <div class="field"><span class="label">Ícone</span>${iconPickerHTML(data.icon)}</div>
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
          const iconName = form.elements.icon.value || DEFAULT_PROJECT_ICON;
          const preview = $('[data-preview-icon]', drawer);
          preview.className = `project-icon project-icon-lg pc-${color}`;
          preview.innerHTML = projectIcon(iconName);
          $('[data-preview-name]', drawer).textContent = form.elements.name.value.trim() || 'Nome do projeto';
          $('[data-preview-desc]', drawer).textContent = form.elements.description.value.trim() || 'Sem descrição';
        };
        const grid = $('[data-icon-grid]', drawer);
        const hint = $('[data-icon-hint]', drawer);
        const selectIcon = (name) => {
          form.elements.icon.value = name;
          $$('[data-icon-pick]', grid).forEach((btn) => {
            const isSelected = btn.dataset.iconPick === name;
            btn.classList.toggle('is-selected', isSelected);
            btn.setAttribute('aria-checked', String(isSelected));
          });
          updatePreview();
        };
        grid.addEventListener('click', (event) => {
          const btn = event.target.closest('[data-icon-pick]');
          if (!btn) return;
          selectIcon(btn.dataset.iconPick);
        });
        const searchInput = $('[data-icon-search]', drawer);
        searchInput.addEventListener('input', () => {
          const query = searchInput.value.trim();
          if (!query) {
            hint.hidden = false;
            grid.innerHTML = iconGridButtonsHTML(PROJECT_ICON_COMMON, form.elements.icon.value);
            return;
          }
          hint.hidden = true;
          grid.innerHTML = iconGridButtonsHTML(searchProjectIcons(query).slice(0, 60), form.elements.icon.value);
        });
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
    const iconName = form.elements.icon.value || DEFAULT_PROJECT_ICON;
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
