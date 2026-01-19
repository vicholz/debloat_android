/**
 * =============================================================================
 * Universal Android Debloater - Web Application
 * =============================================================================
 * 
 * This is the main UI controller for the web-based Android Debloater tool.
 * It handles user interactions and orchestrates calls to the ADB client.
 * 
 * FEATURES:
 * ---------
 * - USB device selection and connection via WebUSB
 * - List all installed Android packages
 * - Enable/disable packages for current user
 * - Uninstall packages for current user
 * - Save/load package selection lists
 * - Export/import lists as JSON files
 * 
 * ARCHITECTURE:
 * -------------
 * - Uses AdbUsbClient from adb_usb.js for USB/ADB communication
 * - State managed in module-level variables
 * - DOM elements cached at startup for efficiency
 * - All async operations use try/catch with user-friendly error messages
 */

import { AdbUsbClient } from "./adb_usb.js";

// =============================================================================
// DOM Element References
// =============================================================================
// All UI elements are cached at startup to avoid repeated DOM queries.

// USB Connection Panel
const streamTimeoutInput = document.getElementById("streamTimeout");
const selectUsbBtn = document.getElementById("selectUsbBtn");
const connectUsbBtn = document.getElementById("connectUsbBtn");
const disconnectUsbBtn = document.getElementById("disconnectUsbBtn");
const deviceInfo = document.getElementById("deviceInfo");
const connectionStatus = document.getElementById("connectionStatus");

// Apps Panel
const loadAppsBtn = document.getElementById("loadAppsBtn");
const selectAllBtn = document.getElementById("selectAllBtn");
const clearSelectionBtn = document.getElementById("clearSelectionBtn");
const filterInput = document.getElementById("filterInput");
const appList = document.getElementById("appList");
const selectionCount = document.getElementById("selectionCount");
const packageCount = document.getElementById("packageCount");

// Bulk Actions (in Apps panel header)
const disableBtn = document.getElementById("disableBtn");
const enableBtn = document.getElementById("enableBtn");
const uninstallBtn = document.getElementById("uninstallBtn");

// Saved Lists Panel
const savedListNameInput = document.getElementById("savedListName");
const saveListBtn = document.getElementById("saveListBtn");
const savedListsSelect = document.getElementById("savedListsSelect");
const loadListBtn = document.getElementById("loadListBtn");
const deleteListBtn = document.getElementById("deleteListBtn");
const savedListInfo = document.getElementById("savedListInfo");
const loadLastBtn = document.getElementById("loadLastBtn");
const lastSelectedInfo = document.getElementById("lastSelectedInfo");
const exportListBtn = document.getElementById("exportListBtn");
const importListBtn = document.getElementById("importListBtn");
const importFileInput = document.getElementById("importFileInput");

// Log Panel
const logOutput = document.getElementById("logOutput");
const copyLogBtn = document.getElementById("copyLogBtn");

// =============================================================================
// LocalStorage Keys
// =============================================================================
const STORAGE_KEY = "uad.savedLists";       // Saved package lists
const LAST_SELECTED_KEY = "uad.lastSelected"; // Auto-saved last selection

// =============================================================================
// Application State
// =============================================================================
let packages = [];                // Array of all package names from device
let selectedPackages = new Set(); // Currently selected packages
let disabledPackages = new Set(); // Set of packages that are currently disabled
let savedLists = {};              // Map of list name -> array of package names
let lastSelected = null;          // Last auto-saved selection
let adbClient = null;             // AdbUsbClient instance when connected
let usbDisconnectHandler = null;  // Handler for USB disconnect events
let selectedUsbDevice = null;     // Selected USB device info (before connect)
let isConnecting = false;         // True while connection is in progress

// =============================================================================
// Logging Functions
// =============================================================================

/**
 * Log a message to the UI log panel with timestamp.
 * @param {string} message - Message to display
 */
function log(message) {
  const timestamp = new Date().toLocaleTimeString();
  logOutput.textContent += `[${timestamp}] ${message}\n`;
  logOutput.scrollTop = logOutput.scrollHeight; // Auto-scroll to bottom
}

/**
 * Log diagnostic payload to browser console.
 * Used for debugging USB/ADB communication issues.
 * @param {Object} payload - Diagnostic data
 */
function logDiag(payload) {
  console.log("[UAD Diagnostics]", payload);
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Wrap a promise with a timeout.
 * 
 * @param {Promise} promise - Promise to wrap
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {string} label - Label for error message
 * @returns {Promise} Promise that rejects on timeout
 */
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

/**
 * Copy text to clipboard with user feedback.
 */
async function copyPanelText(panelName, text) {
  try {
    await navigator.clipboard.writeText(text);
    log(`${panelName} copied to clipboard.`);
  } catch (error) {
    log(`Failed to copy ${panelName}.`);
  }
}

// =============================================================================
// UI State Management
// =============================================================================

/**
 * Update connection status indicator.
 * @param {boolean} connected - Whether device is connected
 */
function setStatus(connected) {
  connectionStatus.textContent = connected ? "USB Connected" : "Disconnected";
  connectionStatus.classList.toggle("connected", connected);
  disconnectUsbBtn.disabled = !connected;
}

/**
 * Enable/disable UI elements during connection operations.
 * Prevents user interaction while async operations are in progress.
 * @param {boolean} isBusy - Whether an operation is in progress
 */
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

/**
 * Update device info display text.
 */
function updateDeviceInfo(text) {
  deviceInfo.textContent = text || "No device connected.";
}

// =============================================================================
// App List Rendering
// =============================================================================

/**
 * Render the list of packages in the UI.
 * 
 * Features:
 * - Filters packages based on search input
 * - Shows checkboxes for multi-select
 * - Shows Enable/Disable button based on current package state
 * - Shows Uninstall button for each package
 */
function renderAppList() {
  const filter = filterInput.value.trim().toLowerCase();
  appList.innerHTML = "";
  const fragment = document.createDocumentFragment();
  let visibleCount = 0;

  packages.forEach((pkg) => {
    // Apply filter
    if (filter && !pkg.toLowerCase().includes(filter)) return;
    visibleCount += 1;

    // Create list item
    const li = document.createElement("li");
    li.className = "app-item";

    // Checkbox for selection
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
      saveCurrentSelectionAsLast(); // Auto-save selection
    });

    // Package name label
    const label = document.createElement("span");
    label.textContent = pkg;

    // Action buttons container
    const actions = document.createElement("div");
    actions.className = "actions";

    // Enable/Disable toggle button
    // Shows "Enable" if package is disabled, "Disable" if enabled
    const isDisabled = disabledPackages.has(pkg);
    const toggleBtn = document.createElement("button");
    toggleBtn.textContent = isDisabled ? "Enable" : "Disable";
    toggleBtn.className = isDisabled ? "primary" : "danger";
    toggleBtn.addEventListener("click", async () => {
      const action = isDisabled ? "enable" : "disable";
      await runPackageAction(action, [pkg]);
      // Update local state and re-render
      if (action === "disable") {
        disabledPackages.add(pkg);
      } else {
        disabledPackages.delete(pkg);
      }
      renderAppList();
    });

    // Uninstall button
    const uninstallBtn = document.createElement("button");
    uninstallBtn.textContent = "Uninstall";
    uninstallBtn.className = "danger";
    uninstallBtn.addEventListener("click", () => {
      runPackageAction("uninstall", [pkg]);
    });

    actions.append(toggleBtn, uninstallBtn);
    li.append(checkbox, label, actions);
    fragment.appendChild(li);
  });

  appList.appendChild(fragment);
  packageCount.textContent = `${visibleCount} shown`;
}

/**
 * Update the selection count display.
 */
function updateSelectionCount() {
  selectionCount.textContent = `${selectedPackages.size} selected`;
}

// =============================================================================
// Last Selected (Auto-Save) Functions
// =============================================================================

/**
 * Load last selection from localStorage.
 */
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

/**
 * Save current selection to localStorage as "last selected".
 * Called automatically whenever selection changes.
 */
function saveLastSelectedToStorage() {
  const payload = {
    packages: Array.from(selectedPackages).sort(),
    savedAt: new Date().toISOString(),
  };
  localStorage.setItem(LAST_SELECTED_KEY, JSON.stringify(payload));
  lastSelected = payload;
  updateLastSelectedInfo();
}

/**
 * Update the last selected info display.
 */
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

// =============================================================================
// Saved Lists Functions
// =============================================================================

/**
 * Load saved lists from localStorage.
 */
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

/**
 * Save lists to localStorage.
 */
function saveListsToStorage() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(savedLists));
}

/**
 * Update the saved list info display.
 */
function updateSavedListInfo() {
  const name = savedListsSelect.value;
  if (!name || !savedLists[name]) {
    savedListInfo.textContent = "No saved list selected.";
    return;
  }
  savedListInfo.textContent = `Selected list: ${name} (${savedLists[name].length} packages).`;
}

/**
 * Refresh the saved lists dropdown.
 */
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

/**
 * Auto-save current selection.
 */
function saveCurrentSelectionAsLast() {
  saveLastSelectedToStorage();
}

/**
 * Save current selection as a named list.
 */
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

/**
 * Load the last auto-saved selection.
 */
function loadLastSelectedList() {
  if (!lastSelected || !lastSelected.packages.length) {
    log("No last selection to load.");
    return;
  }
  if (!packages.length) {
    log("Load apps from the device first.");
    return;
  }
  // Match against currently installed packages
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

/**
 * Load a saved list.
 */
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

/**
 * Delete a saved list.
 */
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

// =============================================================================
// Export/Import Functions
// =============================================================================

/**
 * Export current selection or saved list as JSON file.
 */
function exportList() {
  let name = savedListsSelect.value;
  let packagesToExport;
  
  if (selectedPackages.size > 0) {
    // Export current selection
    name = name || "selection";
    packagesToExport = Array.from(selectedPackages);
  } else if (name && savedLists[name]) {
    // Export saved list
    packagesToExport = savedLists[name];
  } else {
    log("Select packages or a saved list to export.");
    return;
  }
  
  const data = {
    name,
    packages: packagesToExport,
    exportedAt: new Date().toISOString(),
  };
  
  // Create and download file
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name.replace(/[^a-z0-9_-]/gi, "_")}.json`;
  a.click();
  URL.revokeObjectURL(url);
  log(`Exported ${packagesToExport.length} packages as "${a.download}".`);
}

/**
 * Import a list from a JSON or text file.
 * @param {File} file - File to import
 */
function importList(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const content = e.target.result;
      let data;
      
      // Try JSON first
      try {
        data = JSON.parse(content);
      } catch {
        // Fallback: treat as plain text list (one package per line)
        const lines = content.split("\n").map(l => l.trim()).filter(Boolean);
        data = { name: file.name.replace(/\.[^.]+$/, ""), packages: lines };
      }
      
      if (!data.packages || !Array.isArray(data.packages)) {
        throw new Error("Invalid file format: missing packages array");
      }
      
      const name = data.name || file.name.replace(/\.[^.]+$/, "");
      savedLists[name] = data.packages;
      saveListsToStorage();
      refreshSavedListSelect();
      savedListsSelect.value = name;
      log(`Imported list "${name}" with ${data.packages.length} packages.`);
    } catch (error) {
      log(`Import failed: ${error.message}`);
    }
  };
  reader.readAsText(file);
}

// =============================================================================
// USB Connection Functions
// =============================================================================

/**
 * Connect to a previously selected USB device.
 * Establishes ADB connection and sets up the client.
 */
async function connectUsb() {
  const timeout = Number(streamTimeoutInput.value) || 5000;
  try {
    // Disconnect if already connected
    if (adbClient) {
      await disconnectUsb();
    }
    if (!selectedUsbDevice) {
      log("Select a USB device first.");
      return;
    }
    
    log("Connecting to USB device...");
    setConnectingState(true);
    
    // Create new ADB client and connect
    adbClient = new AdbUsbClient({ streamTimeoutMs: timeout });
    const info = await withTimeout(
      adbClient.connect(selectedUsbDevice),
      timeout,
      "USB connect"
    );
    
    // Connection successful
    setStatus(true);
    updateDeviceInfo(
      `Connected: ${info.model} (${info.product}) - serial ${info.serial}`
    );
    log("USB device connected.");
    
    // Log diagnostics for debugging
    logDiag({ event: "connect", diagnostics: adbClient.getDiagnostics() });
    logDiag({
      event: "connect_full",
      diagnostics: adbClient.getFullDiagnostics(),
    });
    
  } catch (error) {
    // Connection failed
    setStatus(false);
    updateDeviceInfo("No device connected.");
    
    // Log timeout-specific diagnostics
    if (adbClient && error && /timed out/i.test(error.message || "")) {
      logDiag({
        event: "connect_timeout",
        diagnostics: adbClient.getFullDiagnostics(),
      });
    }
    
    // Clean up failed client
    if (adbClient) {
      try {
        await adbClient.disconnect();
      } catch (disconnectError) {
        // ignore
      }
    }
    
    // Log error diagnostics
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

/**
 * Open the USB device picker dialog.
 * User must select a device before connecting.
 */
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

/**
 * Disconnect from the current USB device.
 */
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

// =============================================================================
// Package Operations
// =============================================================================

/**
 * Load list of packages from connected device.
 */
async function loadPackages() {
  if (!adbClient) {
    log("Connect a USB device first.");
    return;
  }
  try {
    setStatus(true);
    log("Listing packages from device...");
    packages = await adbClient.listPackages();
    
    log("Getting disabled packages...");
    disabledPackages = await adbClient.listDisabledPackages();
    
    selectedPackages = new Set();
    renderAppList();
    updateSelectionCount();
    log(`Loaded ${packages.length} packages (${disabledPackages.size} disabled).`);
  } catch (error) {
    setStatus(false);
    log(error.message || "Failed to list packages.");
  }
}

/**
 * Select all visible packages (respecting current filter).
 */
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

/**
 * Clear all selections.
 */
function clearSelection() {
  selectedPackages = new Set();
  renderAppList();
  updateSelectionCount();
  saveCurrentSelectionAsLast();
}

/**
 * Run a package action (disable/enable/uninstall) on a list of packages.
 * 
 * @param {string} action - "disable", "enable", or "uninstall"
 * @param {string[]} packageList - Array of package names
 */
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

// =============================================================================
// Event Listeners
// =============================================================================

// USB Connection
connectUsbBtn.addEventListener("click", connectUsb);
selectUsbBtn.addEventListener("click", selectUsbDevice);
disconnectUsbBtn.addEventListener("click", disconnectUsb);

// Apps List
loadAppsBtn.addEventListener("click", loadPackages);
filterInput.addEventListener("input", renderAppList);
selectAllBtn.addEventListener("click", selectAllVisible);
clearSelectionBtn.addEventListener("click", clearSelection);

// Bulk Actions
disableBtn.addEventListener("click", () =>
  runPackageAction("disable", Array.from(selectedPackages))
);
enableBtn.addEventListener("click", () =>
  runPackageAction("enable", Array.from(selectedPackages))
);
uninstallBtn.addEventListener("click", () =>
  runPackageAction("uninstall", Array.from(selectedPackages))
);

// Saved Lists
saveListBtn.addEventListener("click", saveCurrentList);
loadListBtn.addEventListener("click", loadSavedList);
deleteListBtn.addEventListener("click", deleteSavedList);
exportListBtn.addEventListener("click", exportList);
importListBtn.addEventListener("click", () => importFileInput.click());
importFileInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    importList(e.target.files[0]);
    e.target.value = ""; // Reset for next import
  }
});
savedListsSelect.addEventListener("change", updateSavedListInfo);
loadLastBtn.addEventListener("click", loadLastSelectedList);

// Log Panel
copyLogBtn.addEventListener("click", () =>
  copyPanelText("Log", logOutput.textContent)
);

// =============================================================================
// Initialization
// =============================================================================

// Set initial UI state
setStatus(false);

// Load saved data from localStorage
savedLists = loadSavedListsFromStorage();
refreshSavedListSelect();
lastSelected = loadLastSelectedFromStorage();
updateLastSelectedInfo();

// Welcome message
log("Ready. Connect a USB device via WebUSB.");

// Listen for USB disconnect events
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
