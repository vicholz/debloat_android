const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const KEY_STORAGE = "uad.adbKeyPair";
const AUTH_TOKEN = 1;
const AUTH_SIGNATURE = 2;
const AUTH_RSAPUBLICKEY = 3;

const SHA1_DIGEST_LENGTH = 20;
const SHA1_DIGEST_INFO = new Uint8Array([
  0x30,
  0x0d + SHA1_DIGEST_LENGTH,
  0x30,
  0x09,
  0x06,
  0x05,
  1 * 40 + 3,
  14,
  3,
  2,
  26,
  0x05,
  0x00,
  0x04,
  SHA1_DIGEST_LENGTH,
]);

const COMMANDS = {
  AUTH: commandToInt("AUTH"),
  CNXN: commandToInt("CNXN"),
  CLSE: commandToInt("CLSE"),
  OKAY: commandToInt("OKAY"),
  OPEN: commandToInt("OPEN"),
  WRTE: commandToInt("WRTE"),
};

const ADB_FEATURES = [
  "shell_v2",
  "cmd",
  "stat_v2",
  "ls_v2",
  "fixed_push_mkdir",
  "apex",
  "abb",
  "fixed_push_symlink_timestamp",
  "abb_exec",
  "remount_shell",
  "track_app",
  "sendrecv_v2",
  "sendrecv_v2_brotli",
  "sendrecv_v2_lz4",
  "sendrecv_v2_zstd",
  "sendrecv_v2_dry_run_send",
  "devraw",
  "app_info",
  "delayed_ack",
];

function commandToInt(command) {
  return (
    command.charCodeAt(0) |
    (command.charCodeAt(1) << 8) |
    (command.charCodeAt(2) << 16) |
    (command.charCodeAt(3) << 24)
  );
}

function intToCommand(value) {
  return String.fromCharCode(
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff
  );
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return textEncoder.encode(value);
  return new Uint8Array(0);
}

function adbChecksum(bytes) {
  let sum = 0;
  for (const byte of bytes) {
    sum = (sum + byte) >>> 0;
  }
  return sum;
}

function buildHeader(command, arg0, arg1, payloadLength, checksum) {
  const buffer = new ArrayBuffer(24);
  const view = new DataView(buffer);
  view.setUint32(0, command, true);
  view.setUint32(4, arg0, true);
  view.setUint32(8, arg1, true);
  view.setUint32(12, payloadLength, true);
  view.setUint32(16, checksum, true);
  view.setUint32(20, command ^ 0xffffffff, true);
  return new Uint8Array(buffer);
}

function parseProperties(payload) {
  const text = payload.replace(/\0/g, "");
  const parts = text.split("::");
  const propsText = parts.length > 1 ? parts[1] : "";
  const props = {};
  propsText.split(";").forEach((entry) => {
    if (!entry) return;
    const [key, value] = entry.split("=");
    if (key) props[key.trim()] = (value || "").trim();
  });
  return props;
}

function matchUsbInterface(alternate) {
  return (
    alternate.interfaceClass === 0xff &&
    alternate.interfaceSubclass === 0x42 &&
    alternate.interfaceProtocol === 0x01
  );
}

function findUsbInterface(device) {
  for (const configuration of device.configurations || []) {
    for (const interface_ of configuration.interfaces) {
      for (const alternate of interface_.alternates) {
        if (matchUsbInterface(alternate)) {
          return { configuration, interface_, alternate };
        }
      }
    }
  }
  return null;
}

function findUsbEndpoints(endpoints) {
  let inEndpoint;
  let outEndpoint;
  for (const endpoint of endpoints) {
    if (endpoint.direction === "in") {
      inEndpoint = endpoint;
    } else if (endpoint.direction === "out") {
      outEndpoint = endpoint;
    }
    if (inEndpoint && outEndpoint) break;
  }
  if (!inEndpoint || !outEndpoint) {
    throw new Error("ADB endpoints not found on selected interface.");
  }
  return { inEndpoint, outEndpoint };
}

function base64UrlToBytes(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function bigIntToLEBytes(value, length) {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i += 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function bigIntToBEBytes(value, length) {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function powMod(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % modulus;
    }
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function modInverse32(n0) {
  const modulus = 1n << 32n;
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = n0 % modulus;
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r > 1n) {
    throw new Error("n0 is not invertible");
  }
  if (t < 0n) t += modulus;
  const inv = t & 0xffffffffn;
  return Number((modulus - inv) & 0xffffffffn);
}

function buildAndroidRsaPublicKey(n, e, bits) {
  const modulusBytes = bits / 8;
  const n0 = n & 0xffffffffn;
  const n0inv = modInverse32(n0);
  const rr = (1n << BigInt(bits * 2)) % n;

  const buffer = new ArrayBuffer(4 + 4 + modulusBytes + modulusBytes + 4);
  const view = new DataView(buffer);
  view.setUint32(0, modulusBytes / 4, true);
  view.setUint32(4, n0inv, true);
  const nLe = bigIntToLEBytes(n, modulusBytes);
  const rrLe = bigIntToLEBytes(rr, modulusBytes);
  new Uint8Array(buffer, 8, modulusBytes).set(nLe);
  new Uint8Array(buffer, 8 + modulusBytes, modulusBytes).set(rrLe);
  view.setUint32(8 + modulusBytes + modulusBytes, Number(e), true);
  return new Uint8Array(buffer);
}

function buildPublicKeyPayload(publicJwk) {
  const nBytes = base64UrlToBytes(publicJwk.n);
  const eBytes = base64UrlToBytes(publicJwk.e);
  const n = bytesToBigInt(nBytes);
  const e = bytesToBigInt(eBytes);
  const pubkey = buildAndroidRsaPublicKey(n, e, 2048);
  const base64 = bytesToBase64(pubkey);
  return textEncoder.encode(`${base64} adb@webusb\0`);
}

async function rsaSignAdbToken(token, privateJwk) {
  const nBytes = base64UrlToBytes(privateJwk.n);
  const dBytes = base64UrlToBytes(privateJwk.d);
  const n = bytesToBigInt(nBytes);
  const d = bytesToBigInt(dBytes);
  const modulusBytes = nBytes.length;

  let data = token;
  if (data.length !== SHA1_DIGEST_LENGTH) {
    const digest = await crypto.subtle.digest("SHA-1", data);
    data = new Uint8Array(digest);
  }

  const padded = new Uint8Array(modulusBytes);
  let index = 0;
  padded[index++] = 0x00;
  padded[index++] = 0x01;
  const fillLength =
    padded.length - SHA1_DIGEST_INFO.length - data.length - 1;
  while (index < fillLength) {
    padded[index++] = 0xff;
  }
  padded[index++] = 0x00;
  padded.set(SHA1_DIGEST_INFO, index);
  index += SHA1_DIGEST_INFO.length;
  padded.set(data, index);

  const signature = powMod(bytesToBigInt(padded), d, n);
  return bigIntToBEBytes(signature, modulusBytes);
}

export class AdbUsbClient {
  constructor({ streamTimeoutMs = 15000 } = {}) {
    this.streamTimeoutMs = streamTimeoutMs;
    this.device = null;
    this.configurationRef = null;
    this.interfaceRef = null;
    this.alternateRef = null;
    this.interfaceNumber = null;
    this.inEndpoint = null;
    this.outEndpoint = null;
    this.inPacketSize = null;
    this.outPacketSize = null;
    this.readSize = 4096;
    this.maxPayload = 4096;
    this.deviceProperties = {};
    this.packetLog = [];
    this.waiters = [];
    this.streams = new Map();
    this.nextLocalId = 1;
    this.readLoopActive = false;
    this.readLoopRunning = false;
    this.keyPairPromise = null;
    this.publicKeyPayload = null;
    this.authSentPublicKey = false;
    this.authSentSignature = false;
    this.lastDiagnostics = null;
  }

  static async requestDevice() {
    const device = await navigator.usb.requestDevice({
      filters: [
        { classCode: 0xff, subclassCode: 0x42, protocolCode: 0x01 },
      ],
    });
    const interfaceInfo = findUsbInterface(device);
    if (!interfaceInfo) {
      throw new Error("No ADB interface found on device.");
    }
    return { device, interfaceInfo };
  }

  isSameDevice(device) {
    if (!this.device || !device) return false;
    return (
      this.device.vendorId === device.vendorId &&
      this.device.productId === device.productId &&
      (this.device.serialNumber || "") === (device.serialNumber || "")
    );
  }

  getDiagnostics() {
    if (!this.device) {
      return { connected: false };
    }
    const config = this.device.configuration;
    const diagnostics = {
      connected: true,
      vendorId: this.device.vendorId,
      productId: this.device.productId,
      productName: this.device.productName || null,
      serialNumber: this.device.serialNumber || null,
      configurationValue: config ? config.configurationValue : null,
      interfaceNumber: this.interfaceNumber,
      alternateSetting: this.alternateRef
        ? this.alternateRef.alternateSetting
        : null,
      inEndpoint: this.inEndpoint,
      outEndpoint: this.outEndpoint,
      inPacketSize: this.inPacketSize,
      outPacketSize: this.outPacketSize,
      readSize: this.readSize,
      packetLog: this.packetLog.slice(-50),
    };
    this.lastDiagnostics = diagnostics;
    return diagnostics;
  }

  getFullDiagnostics() {
    if (!this.device) return { connected: false };
    const configs = (this.device.configurations || []).map((config) => ({
      configurationValue: config.configurationValue,
      interfaces: config.interfaces.map((iface) => ({
        interfaceNumber: iface.interfaceNumber,
        alternates: iface.alternates.map((alt) => ({
          alternateSetting: alt.alternateSetting,
          class: alt.interfaceClass,
          subclass: alt.interfaceSubclass,
          protocol: alt.interfaceProtocol,
          endpoints: alt.endpoints.map((endpoint) => ({
            direction: endpoint.direction,
            type: endpoint.type,
            endpointNumber: endpoint.endpointNumber,
            packetSize: endpoint.packetSize,
          })),
        })),
      })),
    }));
    const diagnostics = {
      ...this.getDiagnostics(),
      configurations: configs,
    };
    this.lastDiagnostics = diagnostics;
    return diagnostics;
  }

  async connect(deviceInfo) {
    const info = deviceInfo || (await AdbUsbClient.requestDevice());
    const device = info.device;
    let interfaceInfo = info.interfaceInfo;
    await device.open();
    this.device = device;
    try {
      const refreshed = findUsbInterface(device);
      if (refreshed) {
        interfaceInfo = refreshed;
        info.interfaceInfo = refreshed;
      }
      if (!interfaceInfo) {
        throw new Error("No ADB interface found on device.");
      }

      this.configurationRef = interfaceInfo.configuration;
      this.interfaceRef = interfaceInfo.interface_;
      this.alternateRef = interfaceInfo.alternate;
      this.interfaceNumber = interfaceInfo.interface_.interfaceNumber;
      this.authSentPublicKey = false;
      this.authSentSignature = false;

      const { inEndpoint, outEndpoint } = await this.claimInterface(
        device,
        interfaceInfo
      );
      this.inEndpoint = inEndpoint.endpointNumber;
      this.outEndpoint = outEndpoint.endpointNumber;
      this.inPacketSize = inEndpoint.packetSize || 512;
      this.outPacketSize = outEndpoint.packetSize || 512;
      this.readSize = Math.min(
        Math.max(this.inPacketSize * 16, 512),
        16384
      );

      await this.clearHaltSafe("in");
      await this.clearHaltSafe("out");
      this.resetSessionState();
      this.ensureReadLoop();
      await this.sendCnxn();
      const cnxn = await this.waitForPacket("CNXN", 8000);

      this.maxPayload = cnxn.arg1 || this.maxPayload;
      this.deviceProperties = parseProperties(
        textDecoder.decode(cnxn.payload)
      );

      const serial =
        this.deviceProperties["ro.serialno"] ||
        this.device.serialNumber ||
        "unknown";
      return {
        serial,
        product: this.deviceProperties["ro.product.name"] || "unknown",
        model: this.deviceProperties["ro.product.model"] || "unknown",
      };
    } catch (error) {
      try {
        error.diagnostics = this.getFullDiagnostics();
      } catch (diagError) {
        error.diagnostics = this.lastDiagnostics || { connected: false };
      }
      await this.disconnect();
      throw error;
    }
  }

  async claimInterface(device, interfaceInfo) {
    if (
      !device.configuration ||
      device.configuration.configurationValue !==
        interfaceInfo.configuration.configurationValue
    ) {
      await device.selectConfiguration(
        interfaceInfo.configuration.configurationValue
      );
    }
    try {
      await device.claimInterface(interfaceInfo.interface_.interfaceNumber);
    } catch (error) {
      throw new Error(
        "Unable to claim the USB interface. Close any running adb server and reconnect the device."
      );
    }

    if (
      interfaceInfo.interface_.alternate.alternateSetting !==
      interfaceInfo.alternate.alternateSetting
    ) {
      await device.selectAlternateInterface(
        interfaceInfo.interface_.interfaceNumber,
        interfaceInfo.alternate.alternateSetting
      );
    }

    await new Promise((resolve) => setTimeout(resolve, 50));
    return findUsbEndpoints(interfaceInfo.alternate.endpoints);
  }

  async disconnect() {
    this.readLoopActive = false;
    this.waiters.forEach((waiter) => waiter.reject(new Error("Disconnected")));
    this.waiters = [];
    this.streams.clear();

    if (this.device) {
      try {
        await this.device.releaseInterface(this.interfaceNumber);
      } catch (error) {
        // ignore
      }
      try {
        await this.device.close();
      } catch (error) {
        // ignore
      }
    }
    this.device = null;
  }

  async listPackages() {
    const output = await this.runShell("pm list packages");
    return output
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("package:"))
      .map((line) => line.replace("package:", ""))
      .filter(Boolean)
      .sort();
  }

  async runShell(command) {
    const stream = await this.openStream(`shell:${command}`);
    return this.collectStream(stream, this.streamTimeoutMs);
  }

  disablePackage(packageName) {
    return this.runShell(`pm disable-user --user 0 ${packageName}`);
  }

  enablePackage(packageName) {
    return this.runShell(`pm enable ${packageName}`);
  }

  uninstallPackage(packageName) {
    return this.runShell(`pm uninstall --user 0 ${packageName}`);
  }

  async sendCnxn() {
    const version = 0x01000001;
    const maxPayload = 1024 * 1024;
    const features = `host::features=${ADB_FEATURES.join(",")}`;
    await this.sendPacket("CNXN", version, maxPayload, features);
  }

  async openStream(service) {
    const localId = this.nextLocalId++;
    const stream = {
      localId,
      remoteId: null,
      chunks: [],
      closed: false,
      closeResolvers: [],
    };
    stream.ready = new Promise((resolve) => {
      stream.readyResolve = resolve;
    });
    this.streams.set(localId, stream);
    await this.sendPacket("OPEN", localId, 0, `${service}\0`);
    await stream.ready;
    return stream;
  }

  collectStream(stream, timeoutMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve(this.decodeStream(stream));
      }, timeoutMs);
      stream.closeResolvers.push(() => {
        clearTimeout(timer);
        resolve(this.decodeStream(stream));
      });
    });
  }

  decodeStream(stream) {
    const data = new Uint8Array(
      stream.chunks.reduce((sum, chunk) => sum + chunk.length, 0)
    );
    let offset = 0;
    for (const chunk of stream.chunks) {
      data.set(chunk, offset);
      offset += chunk.length;
    }
    return textDecoder.decode(data);
  }

  async sendPacket(command, arg0, arg1, payload) {
    if (!this.device) throw new Error("No device connected.");
    const commandValue = COMMANDS[command] || commandToInt(command);
    const payloadBytes = toUint8Array(payload);
    const checksum = adbChecksum(payloadBytes);
    const header = buildHeader(
      commandValue,
      arg0,
      arg1,
      payloadBytes.length,
      checksum
    );
    this.logPacket("out", commandValue, arg0, arg1, payloadBytes);

    const packetSize = this.outPacketSize || 0;
    const sendChunk = async (chunk) => {
      const safeChunk = chunk.length
        ? new Uint8Array(
            chunk.buffer.slice(
              chunk.byteOffset,
              chunk.byteOffset + chunk.byteLength
            )
          )
        : chunk;
      await this.device.transferOut(this.outEndpoint, safeChunk);
      if (packetSize && chunk.length && chunk.length % packetSize === 0) {
        await this.device.transferOut(this.outEndpoint, new Uint8Array(0));
      }
    };

    try {
      await sendChunk(header);
      if (payloadBytes.length) {
        await sendChunk(payloadBytes);
      }
    } catch (error) {
      if (error && error.name === "NotFoundError") {
        const disconnectError = new Error(
          "USB device disconnected. Reconnect the device and try again."
        );
        disconnectError.cause = error;
        throw disconnectError;
      }
      await this.clearHaltSafe("out");
      try {
        await sendChunk(header);
        if (payloadBytes.length) {
          await sendChunk(payloadBytes);
        }
      } catch (retryError) {
        throw error;
      }
    }
  }

  async waitForPacket(expectedCommand, timeoutMs = 8000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const packet = await this.readPacket();
      if (!packet) continue;
      this.logPacket(
        "in",
        commandToInt(packet.command),
        packet.arg0,
        packet.arg1,
        packet.payload
      );
      if (packet.command === "AUTH") {
        await this.handleAuth(packet);
        continue;
      }
      if (packet.command === expectedCommand) {
        return packet;
      }
    }
    throw new Error("Timed out waiting for device response.");
  }

  ensureReadLoop() {
    if (this.readLoopRunning) return;
    this.readLoopActive = true;
    this.startReadLoop();
  }

  async startReadLoop() {
    this.readLoopRunning = true;
    while (this.readLoopActive && this.device) {
      try {
        const packet = await this.readPacket();
        if (!packet) break;
        this.logPacket(
          "in",
          commandToInt(packet.command),
          packet.arg0,
          packet.arg1,
          packet.payload
        );
        this.dispatchPacket(packet);
      } catch (error) {
        this.readLoopActive = false;
        break;
      }
    }
    this.readLoopRunning = false;
  }

  async readPacket() {
    const packetSize = this.inPacketSize || 512;
    while (true) {
      const headerResult = await this.device.transferIn(
        this.inEndpoint,
        packetSize
      );
      if (!headerResult || headerResult.status !== "ok" || !headerResult.data) {
        return undefined;
      }
      if (headerResult.data.byteLength !== 24) {
        continue;
      }
      const headerView = new DataView(
        headerResult.data.buffer,
        headerResult.data.byteOffset,
        headerResult.data.byteLength
      );
      const command = headerView.getUint32(0, true);
      const arg0 = headerView.getUint32(4, true);
      const arg1 = headerView.getUint32(8, true);
      const length = headerView.getUint32(12, true);
      const magic = headerView.getUint32(20, true);
      if (magic !== (command ^ 0xffffffff)) {
        continue;
      }
      let payload = new Uint8Array(0);
      if (length) {
        const payloadResult = await this.device.transferIn(
          this.inEndpoint,
          length
        );
        if (!payloadResult || payloadResult.status !== "ok" || !payloadResult.data) {
          return undefined;
        }
        payload = new Uint8Array(
          payloadResult.data.buffer,
          payloadResult.data.byteOffset,
          payloadResult.data.byteLength
        );
      }
      return {
        command: intToCommand(command),
        arg0,
        arg1,
        payload,
      };
    }
  }

  dispatchPacket(packet) {
    if (this.waiters.length) {
      for (let i = 0; i < this.waiters.length; i += 1) {
        const waiter = this.waiters[i];
        if (waiter.predicate(packet)) {
          this.waiters.splice(i, 1);
          waiter.resolve(packet);
          return;
        }
      }
    }

    if (packet.command === "OKAY") {
      const localId = packet.arg1;
      const stream = this.streams.get(localId);
      if (stream && !stream.remoteId) {
        stream.remoteId = packet.arg0;
        stream.readyResolve();
      }
      return;
    }

    if (packet.command === "WRTE") {
      const localId = packet.arg1;
      const stream = this.streams.get(localId);
      if (stream) {
        stream.chunks.push(packet.payload);
        this.sendPacket("OKAY", stream.localId, packet.arg0, new Uint8Array());
      }
      return;
    }

    if (packet.command === "CLSE") {
      const localId = packet.arg1;
      const stream = this.streams.get(localId);
      if (stream && !stream.closed) {
        stream.closed = true;
        this.sendPacket("CLSE", stream.localId, packet.arg0, new Uint8Array());
        stream.closeResolvers.forEach((resolve) => resolve());
      }
    }
  }

  waitFor(predicate, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("Timed out waiting for device response."));
      }, timeoutMs);
      this.waiters.push({
        predicate,
        resolve: (packet) => {
          clearTimeout(timer);
          resolve(packet);
        },
        reject,
      });
    });
  }

  async handleAuth(message) {
    if (message.arg0 !== AUTH_TOKEN) {
      return;
    }
    if (!crypto || !crypto.subtle) {
      throw new Error("WebCrypto not available for ADB auth.");
    }
    const { privateKey, publicKeyPayload } = await this.getOrCreateKeyPair();
    this.publicKeyPayload = publicKeyPayload;

    if (!this.authSentSignature) {
      const signature = await rsaSignAdbToken(message.payload, privateKey);
      await this.sendPacket("AUTH", AUTH_SIGNATURE, 0, signature);
      this.authSentSignature = true;
      return;
    }

    if (!this.authSentPublicKey && this.publicKeyPayload) {
      await this.sendPacket("AUTH", AUTH_RSAPUBLICKEY, 0, this.publicKeyPayload);
      this.authSentPublicKey = true;
      return;
    }

    throw new Error("ADB authentication rejected by device.");
  }

  async getOrCreateKeyPair() {
    if (this.keyPairPromise) {
      return this.keyPairPromise;
    }
    this.keyPairPromise = (async () => {
      const stored = localStorage.getItem(KEY_STORAGE);
      if (stored) {
        const { privateJwk, publicJwk } = JSON.parse(stored);
        const publicKeyPayload = buildPublicKeyPayload(publicJwk);
        return { privateKey: privateJwk, publicKeyPayload };
      }

      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-1",
        },
        true,
        ["sign", "verify"]
      );
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      localStorage.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }));
      const publicKeyPayload = buildPublicKeyPayload(publicJwk);
      return { privateKey: privateJwk, publicKeyPayload };
    })();

    return this.keyPairPromise;
  }

  resetSessionState() {
    this.waiters.forEach((waiter) => waiter.reject(new Error("ADB session reset")));
    this.waiters = [];
    this.streams.clear();
    this.nextLocalId = 1;
  }

  async clearHaltSafe(direction) {
    if (!this.device) return;
    const endpoint = direction === "in" ? this.inEndpoint : this.outEndpoint;
    if (endpoint == null) return;
    try {
      await this.device.clearHalt(direction, endpoint);
    } catch (error) {
      // ignore
    }
  }

  logPacket(direction, commandValue, arg0, arg1, payload) {
    const command =
      typeof commandValue === "number"
        ? intToCommand(commandValue)
        : commandValue;
    const payloadBytes = toUint8Array(payload);
    this.packetLog.push({
      ts: new Date().toISOString(),
      direction,
      command,
      arg0,
      arg1,
      length: payloadBytes.length,
      checksum: adbChecksum(payloadBytes),
    });
    if (this.packetLog.length > 200) {
      this.packetLog.splice(0, this.packetLog.length - 200);
    }
  }
}
