import { AdbUsbClient } from "./adb_usb.js";

const streamTimeoutInput = document.getElementById("streamTimeout");
const selectUsbBtn = document.getElementById("selectUsbBtn");
const connectUsbBtn = document.getElementById("connectUsbBtn");
const disconnectUsbBtn = document.getElementById("disconnectUsbBtn");
const deviceInfo = document.getElementById("deviceInfo");
const loadAppsBtn = document.getElementById("loadAppsBtn");
const selectAllBtn = document.getElementById("selectAllBtn");
const clearSelectionBtn = document.getElementById("clearSelectionBtn");
const filterInput = document.getElementById("filterInput");
const appList = document.getElementById("appList");
const selectionCount = document.getElementById("selectionCount");
const packageCount = document.getElementById("packageCount");
const disableBtn = document.getElementById("disableBtn");
const enableBtn = document.getElementById("enableBtn");
const uninstallBtn = document.getElementById("uninstallBtn");
const connectionStatus = document.getElementById("connectionStatus");
const logOutput = document.getElementById("logOutput");
const diagOutput = document.getElementById("diagOutput");
const copyLogBtn = document.getElementById("copyLogBtn");
const copyDiagBtn = document.getElementById("copyDiagBtn");
const savedListNameInput = document.getElementById("savedListName");
const saveListBtn = document.getElementById("saveListBtn");
const savedListsSelect = document.getElementById("savedListsSelect");
const loadListBtn = document.getElementById("loadListBtn");
const deleteListBtn = document.getElementById("deleteListBtn");
const savedListInfo = document.getElementById("savedListInfo");
const loadLastBtn = document.getElementById("loadLastBtn");
const lastSelectedInfo = document.getElementById("lastSelectedInfo");

const STORAGE_KEY = "uad.savedLists";
const LAST_SELECTED_KEY = "uad.lastSelected";

let packages = [];
let selectedPackages = new Set();
let savedLists = {};
let lastSelected = null;
let adbClient = null;
let usbDisconnectHandler = null;
let selectedUsbDevice = null;
let isConnecting = false;

function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  logOutput.textContent += `[${timestamp}] ${message}\n`;
  logOutput.scrollTop = logOutput.scrollHeight;
}

function logDiag(payload) {
  const timestamp = new Date().toLocaleTimeString();
  const text =
    typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  diagOutput.textContent += `[${timestamp}] ${text}\n`;
  diagOutput.scrollTop = diagOutput.scrollHeight;
}

function withTimeout(promise, timeoutMs, label) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

async function copyPanelText(panelName, text) {
  try {
    await navigator.clipboard.writeText(text);
    log(`${panelName} copied to clipboard.`);
  } catch (error) {
    log(`Failed to copy ${panelName}.`);
  }
}

function setStatus(connected) {
  connectionStatus.textContent = connected ? "USB Connected" : "Disconnected";
  connectionStatus.classList.toggle("connected", connected);
  disconnectUsbBtn.disabled = !connected;
}

function setConnectingState(isBusy) {
  isConnecting = isBusy;
  selectUsbBtn.disabled = isBusy;
  connectUsbBtn.disabled = isBusy;
  disconnectUsbBtn.disabled = isBusy || !adbClient;
  loadAppsBtn.disabled = isBusy;
  disableBtn.disabled = isBusy;
  enableBtn.disabled = isBusy;
  uninstallBtn.disabled = isBusy;
  saveListBtn.disabled = isBusy;
  loadListBtn.disabled = isBusy || loadListBtn.disabled;
  deleteListBtn.disabled = isBusy || deleteListBtn.disabled;
  loadLastBtn.disabled = isBusy || loadLastBtn.disabled;
}

function updateDeviceInfo(text) {
  deviceInfo.textContent = text || "No device connected.";
}

function renderAppList() {
  const filter = filterInput.value.trim().toLowerCase();
  appList.innerHTML = "";
  const fragment = document.createDocumentFragment();
  let visibleCount = 0;

  packages.forEach((pkg) => {
    if (filter && !pkg.toLowerCase().includes(filter)) return;
    visibleCount += 1;

    const li = document.createElement("li");
    li.className = "app-item";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedPackages.has(pkg);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        selectedPackages.add(pkg);
      } else {
        selectedPackages.delete(pkg);
      }
      updateSelectionCount();
      saveCurrentSelectionAsLast();
    });

    const label = document.createElement("span");
    label.textContent = pkg;

    const actions = document.createElement("div");
    actions.className = "actions";

    const disableBtn = document.createElement("button");
    disableBtn.textContent = "Disable";
    disableBtn.className = "danger";
    disableBtn.addEventListener("click", () => {
      runPackageAction("disable", [pkg]);
    });

    const uninstallBtn = document.createElement("button");
    uninstallBtn.textContent = "Uninstall";
    uninstallBtn.className = "danger";
    uninstallBtn.addEventListener("click", () => {
      runPackageAction("uninstall", [pkg]);
    });

    actions.append(disableBtn, uninstallBtn);
    li.append(checkbox, label, actions);
    fragment.appendChild(li);
  });

  appList.appendChild(fragment);
  packageCount.textContent = `${visibleCount} shown`;
}

function updateSelectionCount() {
  selectionCount.textContent = `${selectedPackages.size} selected`;
}

function loadLastSelectedFromStorage() {
  try {
    const raw = localStorage.getItem(LAST_SELECTED_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.packages)) return null;
    return parsed;
  } catch (error) {
    log("Failed to read last selection from storage.");
  }
  return null;
}

function saveLastSelectedToStorage() {
  const payload = {
    packages: Array.from(selectedPackages).sort(),
    savedAt: new Date().toISOString(),
  };
  localStorage.setItem(LAST_SELECTED_KEY, JSON.stringify(payload));
  lastSelected = payload;
  updateLastSelectedInfo();
}

function updateLastSelectedInfo() {
  if (!lastSelected || !lastSelected.packages.length) {
    lastSelectedInfo.textContent = "No last selection.";
    loadLastBtn.disabled = true;
    return;
  }
  const time = new Date(lastSelected.savedAt).toLocaleString();
  lastSelectedInfo.textContent = `Last: ${lastSelected.packages.length} package(s) at ${time}`;
  loadLastBtn.disabled = false;
}

function loadSavedListsFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return parsed;
    }
  } catch (error) {
    log("Failed to read saved lists from storage.");
  }
  return {};
}

function saveListsToStorage() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(savedLists));
}

function updateSavedListInfo() {
  const name = savedListsSelect.value;
  if (!name || !savedLists[name]) {
    savedListInfo.textContent = "No saved list selected.";
    return;
  }
  savedListInfo.textContent = `Selected list: ${name} (${savedLists[name].length} packages).`;
}

function refreshSavedListSelect() {
  savedListsSelect.innerHTML = "";
  const names = Object.keys(savedLists).sort();

  if (!names.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No saved lists";
    option.disabled = true;
    option.selected = true;
    savedListsSelect.appendChild(option);
    loadListBtn.disabled = true;
    deleteListBtn.disabled = true;
    updateSavedListInfo();
    return;
  }

  names.forEach((name, index) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = `${name} (${savedLists[name].length})`;
    if (index === 0) option.selected = true;
    savedListsSelect.appendChild(option);
  });
  loadListBtn.disabled = false;
  deleteListBtn.disabled = false;
  updateSavedListInfo();
}

function saveCurrentSelectionAsLast() {
  saveLastSelectedToStorage();
}

function saveCurrentList() {
  const name = savedListNameInput.value.trim();
  if (!name) {
    log("Enter a list name to save.");
    return;
  }
  if (!selectedPackages.size) {
    log("Select at least one package before saving.");
    return;
  }
  savedLists[name] = Array.from(selectedPackages).sort();
  saveListsToStorage();
  refreshSavedListSelect();
  savedListsSelect.value = name;
  updateSavedListInfo();
  log(`Saved list "${name}" with ${savedLists[name].length} packages.`);
}

function loadLastSelectedList() {
  if (!lastSelected || !lastSelected.packages.length) {
    log("No last selection to load.");
    return;
  }
  if (!packages.length) {
    log("Load apps from the device first.");
    return;
  }
  const available = new Set(packages);
  const matched = lastSelected.packages.filter((pkg) => available.has(pkg));
  selectedPackages = new Set(matched);
  renderAppList();
  updateSelectionCount();
  saveCurrentSelectionAsLast();
  const missing = lastSelected.packages.length - matched.length;
  log(
    `Loaded last selection: matched ${matched.length} package(s).` +
      (missing ? ` ${missing} not found on device.` : "")
  );
}

function loadSavedList() {
  const name = savedListsSelect.value;
  if (!name || !savedLists[name]) {
    log("Select a saved list to load.");
    return;
  }
  if (!packages.length) {
    log("Load apps from the device first.");
    return;
  }
  const list = savedLists[name];
  const available = new Set(packages);
  const matched = list.filter((pkg) => available.has(pkg));
  selectedPackages = new Set(matched);
  renderAppList();
  updateSelectionCount();
  saveCurrentSelectionAsLast();
  const missing = list.length - matched.length;
  log(
    `Loaded list "${name}": matched ${matched.length} package(s).` +
      (missing ? ` ${missing} not found on device.` : "")
  );
}

function deleteSavedList() {
  const name = savedListsSelect.value;
  if (!name || !savedLists[name]) {
    log("Select a saved list to delete.");
    return;
  }
  delete savedLists[name];
  saveListsToStorage();
  refreshSavedListSelect();
  log(`Deleted list "${name}".`);
}

async function connectUsb() {
  const timeout = Number(streamTimeoutInput.value) || 15000;
  try {
    if (adbClient) {
      await disconnectUsb();
    }
    if (!selectedUsbDevice) {
      log("Select a USB device first.");
      return;
    }
    log("Connecting to USB device...");
    setConnectingState(true);
    adbClient = new AdbUsbClient({ streamTimeoutMs: timeout });
    const info = await withTimeout(
      adbClient.connect(selectedUsbDevice),
      timeout,
      "USB connect"
    );
    setStatus(true);
    updateDeviceInfo(
      `Connected: ${info.model} (${info.product}) - serial ${info.serial}`
    );
    log("USB device connected.");
    logDiag({ event: "connect", diagnostics: adbClient.getDiagnostics() });
    logDiag({
      event: "connect_full",
      diagnostics: adbClient.getFullDiagnostics(),
    });
  } catch (error) {
    setStatus(false);
    updateDeviceInfo("No device connected.");
    if (adbClient && error && /timed out/i.test(error.message || "")) {
      logDiag({
        event: "connect_timeout",
        diagnostics: adbClient.getFullDiagnostics(),
      });
    }
    if (adbClient) {
      try {
        await adbClient.disconnect();
      } catch (disconnectError) {
        // ignore
      }
    }
    if (error && error.diagnostics) {
      logDiag({ event: "connect_error_full", diagnostics: error.diagnostics });
    } else if (adbClient) {
      logDiag({ event: "connect_error", diagnostics: adbClient.getDiagnostics() });
      logDiag({
        event: "connect_error_full",
        diagnostics: adbClient.getFullDiagnostics(),
      });
    }
    adbClient = null;
    log(error.message || "Failed to connect USB device.");
    if (error && error.cause) {
      logDiag({ event: "connect_error_cause", cause: String(error.cause) });
    }
  } finally {
    setConnectingState(false);
  }
}

async function selectUsbDevice() {
  try {
    log("Selecting USB device...");
    const deviceInfo = await AdbUsbClient.requestDevice();
    selectedUsbDevice = deviceInfo;
    const device = deviceInfo.device;
    updateDeviceInfo(
      `Selected: ${device.productName || "Unknown"} - serial ${
        device.serialNumber || "unknown"
      }`
    );
    log("USB device selected.");
  } catch (error) {
    log(error.message || "Failed to select USB device.");
  }
}
async function disconnectUsb() {
  if (!adbClient) return;
  try {
    await adbClient.disconnect();
  } catch (error) {
    // ignore
  }
  adbClient = null;
  setStatus(false);
  updateDeviceInfo("No device connected.");
  packages = [];
  selectedPackages = new Set();
  renderAppList();
  updateSelectionCount();
  log("USB device disconnected.");
}

async function loadPackages() {
  if (!adbClient) {
    log("Connect a USB device first.");
    return;
  }
  try {
    setStatus(true);
    log("Listing packages from device...");
    packages = await adbClient.listPackages();
    selectedPackages = new Set();
    renderAppList();
    updateSelectionCount();
    log(`Loaded ${packages.length} packages.`);
  } catch (error) {
    setStatus(false);
    log(error.message || "Failed to list packages.");
  }
}

function selectAllVisible() {
  const filter = filterInput.value.trim().toLowerCase();
  packages.forEach((pkg) => {
    if (filter && !pkg.toLowerCase().includes(filter)) return;
    selectedPackages.add(pkg);
  });
  renderAppList();
  updateSelectionCount();
  saveCurrentSelectionAsLast();
}

function clearSelection() {
  selectedPackages = new Set();
  renderAppList();
  updateSelectionCount();
  saveCurrentSelectionAsLast();
}

async function runPackageAction(action, packageList) {
  if (!adbClient) {
    log("Connect a USB device first.");
    return;
  }
  if (!packageList.length) {
    log("Select at least one package.");
    return;
  }
  const actionLabel =
    action === "disable"
      ? "Disable"
      : action === "enable"
      ? "Enable"
      : "Uninstall";
  log(`${actionLabel} ${packageList.length} package(s)...`);

  for (const pkg of packageList) {
    try {
      let output = "";
      if (action === "disable") {
        output = await adbClient.disablePackage(pkg);
      } else if (action === "enable") {
        output = await adbClient.enablePackage(pkg);
      } else {
        output = await adbClient.uninstallPackage(pkg);
      }
      const trimmed = output.trim();
      log(`${actionLabel} ${pkg}: ${trimmed || "OK"}`);
    } catch (error) {
      log(`${actionLabel} ${pkg}: ${error.message || "Failed"}`);
      if (error && error.cause) {
        logDiag({ event: "action_error_cause", package: pkg, cause: String(error.cause) });
      }
    }
  }
}

connectUsbBtn.addEventListener("click", connectUsb);
selectUsbBtn.addEventListener("click", selectUsbDevice);
disconnectUsbBtn.addEventListener("click", disconnectUsb);
loadAppsBtn.addEventListener("click", loadPackages);
filterInput.addEventListener("input", renderAppList);
selectAllBtn.addEventListener("click", selectAllVisible);
clearSelectionBtn.addEventListener("click", clearSelection);
disableBtn.addEventListener("click", () =>
  runPackageAction("disable", Array.from(selectedPackages))
);
enableBtn.addEventListener("click", () =>
  runPackageAction("enable", Array.from(selectedPackages))
);
uninstallBtn.addEventListener("click", () =>
  runPackageAction("uninstall", Array.from(selectedPackages))
);
saveListBtn.addEventListener("click", saveCurrentList);
loadListBtn.addEventListener("click", loadSavedList);
deleteListBtn.addEventListener("click", deleteSavedList);
savedListsSelect.addEventListener("change", updateSavedListInfo);
loadLastBtn.addEventListener("click", loadLastSelectedList);
copyLogBtn.addEventListener("click", () =>
  copyPanelText("Log", logOutput.textContent)
);
copyDiagBtn.addEventListener("click", () =>
  copyPanelText("Diagnostics", diagOutput.textContent)
);

setStatus(false);
savedLists = loadSavedListsFromStorage();
refreshSavedListSelect();
lastSelected = loadLastSelectedFromStorage();
updateLastSelectedInfo();
log("Ready. Connect a USB device via WebUSB.");

if (navigator.usb) {
  usbDisconnectHandler = (event) => {
    if (adbClient && adbClient.isSameDevice(event.device)) {
      log("USB device disconnected.");
      logDiag({ event: "usb_disconnect", diagnostics: adbClient.getDiagnostics() });
      disconnectUsb();
    }
  };
  navigator.usb.addEventListener("disconnect", usbDisconnectHandler);
}
