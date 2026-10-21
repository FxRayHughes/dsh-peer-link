window.__ModuleLoader__.load({
  id: '@local/dsh-peer-link',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useMemo, useCallback, useRef } = React;

    /** Copy for the peer-link configuration page. */
    const zh = {
      summary: '局域网 DSH 互联：委派子代理、续接对端会话',
      statusTitle: '本机',
      name: '名称',
      listening: '监听',
      notListening: '未监听',
      discovery: '局域网发现',
      discoveryOff: '不可用',
      peersTitle: '已配对的对端',
      noPeers: '还没有配对的对端。把另一台的配对码粘贴到下面即可配对。',
      checking: '正在检测…',
      refresh: '刷新',
      unpair: '解除配对',
      unpairConfirm: '再点一次确认',
      pairTitle: '配对',
      pairCode: '对端配对码',
      pairHint: '粘贴另一台的配对码（dshpeer1.…），或该码文件在本机上的绝对路径。配对后对方也会自动加上本机。',
      pairPlaceholder: 'dshpeer1.… 或 /path/to/pairing-code.txt',
      alias: '本地别名（可选）',
      pair: '配对',
      pairing: '正在配对…',
      paired: '已配对：{name}',
      ownCodeTitle: '本机配对码',
      ownCodeHint: '在另一台上粘贴这个码。码里含密钥，只发给自己的设备。',
      showCode: '显示配对码',
      hideCode: '隐藏',
      copy: '复制',
      copied: '已复制',
      codeFile: '文件：{file}',
      network: '网络',
      delegation: '委派',
      access: '对端权限',
      displayName: '显示名称',
      displayNameHint: '本机在对端显示的名称；留空用主机名。',
      listen: '接收对端请求',
      listenHint: '关闭后本机只能调用别人。',
      host: '监听地址',
      hostHint: '0.0.0.0 表示所有网卡。',
      port: 'HTTP 端口',
      portHint: '0 = 随机空闲端口（优先沿用上次），对端自动发现；被占用时自动换。',
      discoveryPort: '发现端口（UDP）',
      discoveryPortHint: '共享绑定，不独占；两侧必须一致。',
      allowCidrs: '允许的地址段',
      allowCidrsHint: '逗号分隔的 CIDR，只有这些地址能连进来。',
      subagentPeer: 'subagent_peer 默认对端',
      subagentPeerHint: '只配对一台时可保持自动。',
      auto: '自动（只有一台时）',
      remoteCwd: '默认远端工作目录',
      remoteCwdHint: '对端机器上的绝对路径；留空时本机目录在对端存在就用它，否则用对端默认目录。',
      delegationNote: '附加无人值守说明',
      delegationNoteHint: '委派任务前告诉对端：无人值守、自行决策、最后汇报。',
      permissionPreset: '对端会话的权限预设',
      permissionPresetHint: '用于对端发来的新会话；无人值守时，需要审批的操作会卡住。',
      presetDefault: '沿用本机默认',
      allowedRoots: '允许的工作目录根',
      allowedRootsHint: '对端只能在这些目录下工作，每行一个；留空不限制。',
      save: '保存',
      saving: '正在保存…',
      saved: '已保存并生效',
      failed: '保存被拒绝',
      reset: '还原',
      readOnly: '此配置为只读（被更高层的配置覆盖）。',
      invalidPort: '须为 0–65535 的整数',
      invalidDiscoveryPort: '须为 1–65535 的整数',
      error: '出错：{message}',
    };
    const en = {
      summary: 'Link DSH instances on the LAN: delegate subagents and continue remote sessions',
      statusTitle: 'This machine',
      name: 'Name',
      listening: 'Listening',
      notListening: 'Not listening',
      discovery: 'LAN discovery',
      discoveryOff: 'Unavailable',
      peersTitle: 'Paired peers',
      noPeers: 'No peers yet. Paste the other machine\'s pairing code below.',
      checking: 'Checking…',
      refresh: 'Refresh',
      unpair: 'Unpair',
      unpairConfirm: 'Click again to confirm',
      pairTitle: 'Pair',
      pairCode: 'Peer pairing code',
      pairHint: 'Paste the other machine\'s pairing code (dshpeer1.…) or the absolute path of a file on this machine holding it. The other side adds this machine automatically.',
      pairPlaceholder: 'dshpeer1.… or /path/to/pairing-code.txt',
      alias: 'Local alias (optional)',
      pair: 'Pair',
      pairing: 'Pairing…',
      paired: 'Paired: {name}',
      ownCodeTitle: 'This machine\'s pairing code',
      ownCodeHint: 'Paste this on the other machine. It contains the secret; share it only with your own devices.',
      showCode: 'Show code',
      hideCode: 'Hide',
      copy: 'Copy',
      copied: 'Copied',
      codeFile: 'File: {file}',
      network: 'Network',
      delegation: 'Delegation',
      access: 'Peer access',
      displayName: 'Display name',
      displayNameHint: 'How peers see this machine; empty uses the hostname.',
      listen: 'Accept peer requests',
      listenHint: 'When off, this machine can only call others.',
      host: 'Listen address',
      hostHint: '0.0.0.0 means every interface.',
      port: 'HTTP port',
      portHint: '0 = a random free port (reusing the last one when possible) that peers discover; a busy port falls back to random.',
      discoveryPort: 'Discovery port (UDP)',
      discoveryPortHint: 'Shared bind, never exclusive; must match on both sides.',
      allowCidrs: 'Allowed address ranges',
      allowCidrsHint: 'Comma-separated CIDRs allowed to connect.',
      subagentPeer: 'subagent_peer default peer',
      subagentPeerHint: 'May stay automatic while only one peer is paired.',
      auto: 'Automatic (single peer)',
      remoteCwd: 'Default remote directory',
      remoteCwdHint: 'Absolute path on the peer; empty uses this machine\'s directory when it exists there, else the peer\'s default.',
      delegationNote: 'Add unattended note',
      delegationNoteHint: 'Tell the remote agent it runs unattended and should decide and report on its own.',
      permissionPreset: 'Permission preset for peer sessions',
      permissionPresetHint: 'Applied to new sessions peers start here; unattended runs stall on approvals.',
      presetDefault: 'This machine\'s default',
      allowedRoots: 'Allowed working roots',
      allowedRootsHint: 'Peers may only work under these directories, one per line; empty allows any.',
      save: 'Save',
      saving: 'Saving…',
      saved: 'Saved and applied',
      failed: 'Save refused',
      reset: 'Reset',
      readOnly: 'This configuration is read-only (overridden by a higher layer).',
      invalidPort: 'Must be a whole number from 0 to 65535',
      invalidDiscoveryPort: 'Must be a whole number from 1 to 65535',
      error: 'Error: {message}',
    };

    const NS = 'peer-link';
    const ROW_KEY = '@local/dsh-peer-link#peer-link';

    /** Config fields in page order; `kind` picks the control. */
    const SECTIONS = [
      {
        title: 'network',
        fields: [
          { key: 'displayName', kind: 'text', placeholder: 'hostname' },
          { key: 'listen', kind: 'switch' },
          { key: 'host', kind: 'text', placeholder: '0.0.0.0' },
          { key: 'port', kind: 'number', min: 0, invalid: 'invalidPort' },
          { key: 'discoveryPort', kind: 'number', min: 1, invalid: 'invalidDiscoveryPort' },
          { key: 'allowCidrs', kind: 'textarea', rows: 2 },
        ],
      },
      {
        title: 'delegation',
        fields: [
          { key: 'subagentPeer', kind: 'peer' },
          { key: 'remoteCwd', kind: 'text', placeholder: 'C:\\work' },
          { key: 'delegationNote', kind: 'switch' },
        ],
      },
      {
        title: 'access',
        fields: [
          { key: 'permissionPreset', kind: 'preset' },
          { key: 'allowedRoots', kind: 'roots', rows: 3, placeholder: '/Users/me/projects' },
        ],
      },
    ];
    const FIELDS = SECTIONS.flatMap((section) => section.fields);

    const CSS = `
.pl-page{display:flex;flex-direction:column;gap:24px;color:var(--dsw-alias-label-primary)}
.pl-section{display:flex;flex-direction:column;gap:10px}
.pl-heading{display:flex;align-items:center;justify-content:space-between;gap:12px}
.pl-title{margin:0;font-size:12px;font-weight:600;line-height:18px;color:var(--dsw-alias-label-secondary)}
.pl-card{display:flex;flex-direction:column;border:.5px solid var(--dsw-alias-border-l2);border-radius:10px;background:var(--dsw-alias-bg-layer-1)}
.pl-card>*+*{border-top:.5px solid var(--dsw-alias-border-l1)}
.pl-row{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:12px 16px}
.pl-row.stack{flex-direction:column;align-items:stretch;gap:8px}
.pl-text{display:flex;flex-direction:column;gap:2px;min-width:0}
.pl-label{font-size:14px;line-height:20px}
.pl-hint{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.pl-mono{font:12px/18px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.pl-value{text-align:right}
.pl-control{flex:0 0 260px;min-width:0;display:flex;flex-direction:column;gap:4px}
.pl-input,.pl-select,.pl-area{box-sizing:border-box;width:100%;font-family:inherit;font-size:14px;line-height:20px;padding:6px 10px;border-radius:6px;border:.5px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);outline:none}
.pl-area{resize:vertical;font:12px/18px ui-monospace,SFMono-Regular,Menlo,monospace}
.pl-input:focus,.pl-select:focus,.pl-area:focus{border-color:var(--dsw-alias-brand-primary)}
.pl-input[aria-invalid=true]{border-color:var(--dsw-alias-state-error-primary)}
.pl-input:disabled,.pl-select:disabled,.pl-area:disabled{opacity:.6}
.pl-btn{flex:0 0 auto;font-family:inherit;font-size:13px;line-height:20px;padding:5px 12px;border-radius:6px;border:.5px solid var(--dsw-alias-border-l2);background:transparent;color:var(--dsw-alias-label-primary);cursor:pointer;white-space:nowrap}
.pl-btn:hover:not(:disabled){background:var(--dsw-alias-bg-layer-2)}
.pl-btn:disabled{opacity:.5;cursor:default}
.pl-btn.primary{border-color:transparent;background:var(--dsw-alias-brand-primary);color:#fff}
.pl-btn.primary:hover:not(:disabled){background:var(--dsw-alias-brand-primary);filter:brightness(1.08)}
.pl-btn.danger{color:var(--dsw-alias-state-error-primary)}
.pl-switch{position:relative;flex:0 0 auto;width:36px;height:20px;border-radius:10px;border:none;padding:0;cursor:pointer;background:var(--dsw-alias-state-idle-primary);transition:background .15s}
.pl-switch[aria-checked=true]{background:var(--dsw-alias-brand-primary)}
.pl-switch:disabled{opacity:.5;cursor:default}
.pl-switch::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .15s}
.pl-switch[aria-checked=true]::after{transform:translateX(16px)}
.pl-dot{display:inline-block;flex:0 0 auto;width:7px;height:7px;border-radius:50%;margin-right:6px;background:var(--dsw-alias-state-idle-primary);vertical-align:1px}
.pl-dot.on{background:var(--dsw-alias-state-success-primary)}
.pl-dot.off{background:var(--dsw-alias-state-error-primary)}
.pl-peer{display:flex;align-items:center;gap:12px;padding:12px 16px}
.pl-peer .pl-text{flex:1}
.pl-inline{display:flex;gap:8px;align-items:center}
.pl-inline .pl-input{flex:1}
.pl-footer{display:flex;align-items:center;flex-wrap:wrap;gap:12px}
.pl-note{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.pl-note.ok{color:var(--dsw-alias-state-success-primary)}
.pl-note.err{color:var(--dsw-alias-state-error-primary);overflow-wrap:anywhere}
@media (max-width:640px){.pl-row{flex-direction:column;align-items:stretch;gap:8px}.pl-control{flex-basis:auto}.pl-value{text-align:left}}
`;

    /** The plugin's Host route, relative to the page so a base path is kept. */
    function rpc(method, args) {
      return fetch('peer-link/rpc', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ method, args: args ?? {} }),
      }).then(async (response) => {
        let envelope = null;
        try {
          envelope = await response.json();
        } catch {
          envelope = null;
        }
        if (envelope && envelope.ok === true) return envelope.value;
        throw new Error(envelope?.error?.message ?? `HTTP ${response.status}`);
      });
    }

    function fill(text, vars) {
      return text.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? ''));
    }

    function readValue(form) {
      const state = form?.state;
      if (!state) return {};
      const value = state.value ?? state.resolved ?? {};
      return value !== null && typeof value === 'object' ? value : {};
    }

    /** @returns a locale key when the draft value cannot be saved. */
    function invalidOf(field, value) {
      if (field.kind !== 'number') return undefined;
      return Number.isInteger(value) && value >= field.min && value <= 65535 ? undefined : field.invalid;
    }

    const rootsToLines = (value) =>
      String(value ?? '')
        .split(/[;\n]/)
        .map((item) => item.trim())
        .filter(Boolean)
        .join('\n');

    function Switch({ checked, disabled, label, onChange }) {
      return h('button', {
        type: 'button',
        role: 'switch',
        className: 'pl-switch',
        'aria-checked': checked === true,
        'aria-label': label,
        disabled,
        onClick: () => onChange(!checked),
      });
    }

    function Row({ label, hint, stack, children }) {
      return h(
        'div',
        { className: stack ? 'pl-row stack' : 'pl-row' },
        h('div', { className: 'pl-text' }, h('div', { className: 'pl-label' }, label), hint ? h('div', { className: 'pl-hint' }, hint) : null),
        children,
      );
    }

    function Field({ field, value, setValue, disabled, t, peers, presets }) {
      const label = t(field.key);
      const hint = t(`${field.key}Hint`);
      if (field.kind === 'switch') {
        return h(Row, { label, hint }, h(Switch, { checked: value === true, disabled, label, onChange: setValue }));
      }
      if (field.kind === 'textarea' || field.kind === 'roots') {
        return h(
          Row,
          { label, hint, stack: true },
          h('textarea', {
            className: 'pl-area',
            rows: field.rows,
            value: typeof value === 'string' ? value : '',
            placeholder: field.placeholder,
            disabled,
            spellCheck: false,
            'aria-label': label,
            onChange: (event) => setValue(event.target.value),
          }),
        );
      }
      const invalid = invalidOf(field, value);
      let control;
      if (field.kind === 'peer' || field.kind === 'preset') {
        const options =
          field.kind === 'peer'
            ? [{ value: '', name: t('auto') }, ...peers.map((peer) => ({ value: peer.name, name: peer.name }))]
            : [
                { value: '', name: t('presetDefault') },
                ...presets.map((preset) => ({ value: preset.value, name: preset.name && preset.name !== preset.value ? `${preset.name} · ${preset.value}` : preset.value })),
              ];
        // A stored value stays selectable even when it is not offered right now.
        if (value && !options.some((option) => option.value === value)) options.push({ value, name: value });
        control = h(
          'select',
          { className: 'pl-select', value: value ?? '', disabled, 'aria-label': label, onChange: (event) => setValue(event.target.value) },
          options.map((option) => h('option', { key: option.value, value: option.value }, option.name)),
        );
      } else if (field.kind === 'number') {
        control = h('input', {
          className: 'pl-input',
          type: 'number',
          min: field.min,
          max: 65535,
          step: 1,
          value: Number.isFinite(value) ? String(value) : '',
          disabled,
          'aria-label': label,
          'aria-invalid': invalid !== undefined,
          onChange: (event) => setValue(event.target.value === '' ? NaN : Number(event.target.value)),
        });
      } else {
        control = h('input', {
          className: 'pl-input',
          type: 'text',
          value: typeof value === 'string' ? value : '',
          placeholder: field.placeholder,
          disabled,
          autoComplete: 'off',
          spellCheck: false,
          'aria-label': label,
          onChange: (event) => setValue(event.target.value),
        });
      }
      return h(
        Row,
        { label, hint },
        h('div', { className: 'pl-control' }, control, invalid ? h('div', { className: 'pl-note err' }, t(invalid)) : null),
      );
    }

    /** Live status and peers through the plugin's Host route; peers probe the network, so status loads first. */
    function usePeers() {
      const [data, setData] = useState({ status: 'loading', self: null, peers: [], error: null });
      const seq = useRef(0);
      const load = useCallback(() => {
        const mine = ++seq.current;
        setData((current) => ({ ...current, status: 'loading', error: null }));
        rpc('status')
          .then((self) => mine === seq.current && setData((current) => ({ ...current, self })))
          .catch(() => undefined);
        rpc('peers')
          .then((value) => mine === seq.current && setData({ status: 'ready', self: value.self, peers: value.peers, error: null }))
          .catch((error) => mine === seq.current && setData((current) => ({ ...current, status: 'error', error: error.message })));
      }, []);
      useEffect(() => {
        load();
        return () => {
          seq.current += 1;
        };
      }, [load]);
      return [data, load];
    }

    function StatusSection({ t, self }) {
      const listening = self?.listening;
      return h(
        'section',
        { className: 'pl-section' },
        h('h4', { className: 'pl-title' }, t('statusTitle')),
        h(
          'div',
          { className: 'pl-card' },
          h(Row, { label: t('name') }, h('span', { className: 'pl-mono pl-value' }, self?.name ?? '…')),
          h(
            Row,
            { label: t('listening') },
            h(
              'span',
              { className: 'pl-mono pl-value' },
              self ? h('span', { className: listening ? 'pl-dot on' : 'pl-dot off' }) : null,
              self ? listening ?? t('notListening') : '…',
            ),
          ),
          h(Row, { label: t('discovery') }, h('span', { className: 'pl-mono pl-value' }, self ? self.discovery ?? t('discoveryOff') : '…')),
        ),
      );
    }

    function PeerRow({ t, peer, onUnpaired }) {
      const [armed, setArmed] = useState(false);
      const [busy, setBusy] = useState(false);
      const [error, setError] = useState(null);
      useEffect(() => {
        if (!armed) return undefined;
        const timer = setTimeout(() => setArmed(false), 4000);
        return () => clearTimeout(timer);
      }, [armed]);
      const remote = peer.remote;
      const detail = [peer.addr, remote ? `${remote.platform} · ${remote.hostname}` : peer.platform].filter(Boolean).join(' · ');
      const unpair = () => {
        if (!armed) {
          setArmed(true);
          return;
        }
        setBusy(true);
        rpc('unpair', { peer: peer.name })
          .then(() => onUnpaired())
          .catch((err) => {
            setError(err.message);
            setBusy(false);
            setArmed(false);
          });
      };
      return h(
        'div',
        { className: 'pl-peer' },
        h(
          'div',
          { className: 'pl-text' },
          h('div', { className: 'pl-label' }, h('span', { className: peer.online ? 'pl-dot on' : 'pl-dot off' }), peer.name),
          h('div', { className: 'pl-hint pl-mono' }, detail || '—'),
          !peer.online && peer.error ? h('div', { className: 'pl-note err' }, peer.error) : null,
          error ? h('div', { className: 'pl-note err' }, fill(t('error'), { message: error })) : null,
        ),
        h('button', { type: 'button', className: 'pl-btn danger', disabled: busy, onClick: unpair }, armed ? t('unpairConfirm') : t('unpair')),
      );
    }

    function PeersSection({ t, data, reload }) {
      const loading = data.status === 'loading';
      return h(
        'section',
        { className: 'pl-section' },
        h(
          'div',
          { className: 'pl-heading' },
          h('h4', { className: 'pl-title' }, t('peersTitle')),
          h('button', { type: 'button', className: 'pl-btn', disabled: loading, onClick: reload }, loading ? t('checking') : t('refresh')),
        ),
        data.status === 'error' ? h('div', { className: 'pl-note err' }, fill(t('error'), { message: data.error })) : null,
        data.peers.length > 0
          ? h(
              'div',
              { className: 'pl-card' },
              data.peers.map((peer) => h(PeerRow, { key: peer.name, t, peer, onUnpaired: reload })),
            )
          : loading
            ? null
            : h('div', { className: 'pl-note' }, t('noPeers')),
      );
    }

    function PairSection({ t, onPaired }) {
      const [code, setCode] = useState('');
      const [alias, setAlias] = useState('');
      const [busy, setBusy] = useState(false);
      const [note, setNote] = useState(null);
      const [own, setOwn] = useState(null);
      const [copied, setCopied] = useState(false);

      const submit = () => {
        setBusy(true);
        setNote(null);
        rpc('pair', { code, alias })
          .then((value) => {
            setBusy(false);
            setCode('');
            setAlias('');
            setNote({ ok: true, text: fill(t('paired'), { name: value.paired }) });
            onPaired();
          })
          .catch((error) => {
            setBusy(false);
            setNote({ ok: false, text: fill(t('error'), { message: error.message }) });
          });
      };

      const toggleOwn = () => {
        if (own) {
          setOwn(null);
          return;
        }
        rpc('pairingCode')
          .then((value) => setOwn(value))
          .catch((error) => setNote({ ok: false, text: fill(t('error'), { message: error.message }) }));
      };

      const copy = () => {
        navigator.clipboard?.writeText(own.code).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      };

      return h(
        'section',
        { className: 'pl-section' },
        h('h4', { className: 'pl-title' }, t('pairTitle')),
        h(
          'div',
          { className: 'pl-card' },
          h(
            Row,
            { label: t('pairCode'), hint: t('pairHint'), stack: true },
            h('input', {
              className: 'pl-input pl-mono',
              type: 'text',
              value: code,
              placeholder: t('pairPlaceholder'),
              disabled: busy,
              autoComplete: 'off',
              spellCheck: false,
              'aria-label': t('pairCode'),
              onChange: (event) => setCode(event.target.value),
            }),
            h(
              'div',
              { className: 'pl-inline' },
              h('input', {
                className: 'pl-input',
                type: 'text',
                value: alias,
                placeholder: t('alias'),
                disabled: busy,
                autoComplete: 'off',
                'aria-label': t('alias'),
                onChange: (event) => setAlias(event.target.value),
              }),
              h('button', { type: 'button', className: 'pl-btn primary', disabled: busy || code.trim() === '', onClick: submit }, busy ? t('pairing') : t('pair')),
            ),
            note ? h('div', { className: note.ok ? 'pl-note ok' : 'pl-note err', role: 'status' }, note.text) : null,
          ),
          own === null
            ? h(Row, { label: t('ownCodeTitle'), hint: t('ownCodeHint') }, h('button', { type: 'button', className: 'pl-btn', onClick: toggleOwn }, t('showCode')))
            : h(
                Row,
                { label: t('ownCodeTitle'), hint: t('ownCodeHint'), stack: true },
                h('textarea', { className: 'pl-area', rows: 3, readOnly: true, value: own.code, onFocus: (event) => event.target.select() }),
                h(
                  'div',
                  { className: 'pl-inline' },
                  h('span', { className: 'pl-hint pl-mono', style: { flex: 1 } }, fill(t('codeFile'), { file: own.file })),
                  h('button', { type: 'button', className: 'pl-btn', onClick: copy }, copied ? t('copied') : t('copy')),
                  h('button', { type: 'button', className: 'pl-btn', onClick: toggleOwn }, t('hideCode')),
                ),
              ),
        ),
      );
    }

    /** Draft of the plugin's Config, saved as one revision-fenced mutation. */
    function SettingsSections({ t, form, peers, presets, onSaved }) {
      const value = readValue(form);
      const key = JSON.stringify(value);
      const baseline = useMemo(() => {
        const next = { ...value };
        // Roots are stored `;`-separated but edited one per line.
        next.allowedRoots = rootsToLines(value.allowedRoots);
        return next;
      }, [key]);
      const [draft, setDraft] = useState(baseline);
      const [busy, setBusy] = useState(false);
      const [note, setNote] = useState(null);

      useEffect(() => {
        setDraft(baseline);
      }, [baseline]);

      if (!form) return null;
      const writable = form.state?.writable !== false;
      const disabled = !writable || busy;
      const changed = FIELDS.filter((field) => !Object.is(draft[field.key], baseline[field.key]));
      const invalid = FIELDS.some((field) => invalidOf(field, draft[field.key]) !== undefined);

      const save = async () => {
        const ops = changed.map((field) => {
          let next = draft[field.key];
          if (field.kind === 'roots') next = rootsToLines(next).split('\n').filter(Boolean).join(';');
          return { op: 'set', path: [field.key], value: next };
        });
        if (ops.length === 0) return;
        setBusy(true);
        let ok = false;
        try {
          ok = await form.mutate(ops, form.state?.revision);
        } catch {
          ok = false;
        }
        setBusy(false);
        setNote(ok ? 'saved' : 'failed');
        // The Host restarts its listener asynchronously after a network change.
        if (ok) setTimeout(onSaved, 800);
      };

      return h(
        React.Fragment,
        null,
        SECTIONS.map((section) =>
          h(
            'section',
            { key: section.title, className: 'pl-section' },
            h('h4', { className: 'pl-title' }, t(section.title)),
            h(
              'div',
              { className: 'pl-card' },
              section.fields.map((field) =>
                h(Field, {
                  key: field.key,
                  field,
                  value: draft[field.key],
                  setValue: (next) => {
                    setNote(null);
                    setDraft((current) => ({ ...current, [field.key]: next }));
                  },
                  disabled,
                  t,
                  peers,
                  presets,
                }),
              ),
            ),
          ),
        ),
        h(
          'div',
          { className: 'pl-footer' },
          h('button', { type: 'button', className: 'pl-btn primary', disabled: disabled || changed.length === 0 || invalid, onClick: save }, busy ? t('saving') : t('save')),
          h(
            'button',
            {
              type: 'button',
              className: 'pl-btn',
              disabled: disabled || changed.length === 0,
              onClick: () => {
                setDraft(baseline);
                setNote(null);
              },
            },
            t('reset'),
          ),
          note === null ? null : h('span', { className: note === 'saved' ? 'pl-note ok' : 'pl-note err', role: 'status' }, t(note)),
          writable ? null : h('span', { className: 'pl-note' }, t('readOnly')),
        ),
      );
    }

    function PeerLinkPage({ t, form }) {
      const [data, reload] = usePeers();
      const [presets, setPresets] = useState([]);
      useEffect(() => {
        let live = true;
        rpc('presets')
          .then((value) => live && setPresets(value.options ?? []))
          .catch(() => undefined);
        return () => {
          live = false;
        };
      }, []);
      return h(
        'div',
        { className: 'pl-page', 'data-peer-link-page': true },
        h('style', null, CSS),
        h(StatusSection, { t, self: data.self }),
        h(PeersSection, { t, data, reload }),
        h(PairSection, { t, onPaired: reload }),
        h(SettingsSections, { t, form, peers: data.peers, presets, onSaved: reload }),
      );
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'peer-link: locale');
        ctx.slots.inject('plugins.row.config', () =>
          ctx.slots.register({ name: 'plugins.row.config', key: ROW_KEY, locale: NS }, (props) =>
            props.view === 'summary' ? props.t('summary') : h(PeerLinkPage, props),
          ),
        );
      },
    };
  },
});
