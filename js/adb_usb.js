/**
 * =============================================================================
 * ADB over WebUSB - Protocol Implementation
 * =============================================================================
 * 
 * This module implements the Android Debug Bridge (ADB) protocol over WebUSB,
 * allowing a web browser to communicate directly with Android devices via USB.
 * 
 * OVERVIEW:
 * ---------
 * ADB uses a simple packet-based protocol. Each packet has a 24-byte header
 * followed by an optional payload. Communication happens over USB bulk endpoints.
 * 
 * USB INTERFACE:
 * --------------
 * Android devices expose ADB as a USB interface with:
 * - Class: 0xFF (Vendor Specific)
 * - Subclass: 0x42 (ADB)
 * - Protocol: 0x01
 * - Two bulk endpoints: one IN (device→host) and one OUT (host→device)
 * 
 * CONNECTION FLOW:
 * ----------------
 * 1. Host sends CNXN packet with version, max payload size, and system identity
 * 2. Device responds with AUTH packet containing a 20-byte token
 * 3. Host signs the token with its RSA private key, sends AUTH signature
 * 4. If device doesn't recognize the key, it sends another AUTH token
 * 5. Host sends AUTH with its RSA public key
 * 6. User approves connection on device (or key is already trusted)
 * 7. Device sends CNXN packet confirming connection
 * 
 * STREAM OPERATIONS:
 * ------------------
 * After connection, host can open streams to device services:
 * 1. Host sends OPEN with local-id and service name (e.g., "shell:ls")
 * 2. Device responds with OKAY containing remote-id
 * 3. Device sends WRTE packets with data, host acknowledges with OKAY
 * 4. Either side sends CLSE to close the stream
 */

// Text encoding/decoding utilities for string<->binary conversion
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// LocalStorage key for persisting the RSA key pair across sessions
const KEY_STORAGE = "uad.adbKeyPair";

/**
 * ADB Authentication Types
 * Used in AUTH packet's arg0 field to indicate the type of auth data
 */
const AUTH_TOKEN = 1;         // Device sends: 20-byte random token to sign
const AUTH_SIGNATURE = 2;     // Host sends: RSA signature of the token
const AUTH_RSAPUBLICKEY = 3;  // Host sends: RSA public key for device to store

/**
 * SHA-1 Digest Info for PKCS#1 v1.5 Signature Padding
 * 
 * RSA signatures require PKCS#1 v1.5 padding which includes a DER-encoded
 * DigestInfo structure. This identifies the hash algorithm used (SHA-1).
 * 
 * Structure: SEQUENCE { SEQUENCE { OID sha1, NULL }, OCTET STRING digest }
 * The OID for SHA-1 is 1.3.14.3.2.26 (encoded as 06 05 2B 0E 03 02 1A)
 */
const SHA1_DIGEST_LENGTH = 20;
const SHA1_DIGEST_INFO = new Uint8Array([
  0x30,                       // SEQUENCE tag
  0x0d + SHA1_DIGEST_LENGTH,  // Length of sequence content (13 + 20 = 33)
  0x30,                       // SEQUENCE tag (AlgorithmIdentifier)
  0x09,                       // Length of AlgorithmIdentifier (9 bytes)
  0x06,                       // OBJECT IDENTIFIER tag
  0x05,                       // OID length (5 bytes)
  1 * 40 + 3,                 // 1.3 (first two OID components encoded as 40*1+3=43)
  14,                         // .14
  3,                          // .3
  2,                          // .2
  26,                         // .26 (complete OID: 1.3.14.3.2.26 = SHA-1)
  0x05,                       // NULL tag (algorithm parameters)
  0x00,                       // NULL length
  0x04,                       // OCTET STRING tag (for the digest)
  SHA1_DIGEST_LENGTH,         // Digest length (20 bytes for SHA-1)
]);

/**
 * ADB Command Constants
 * 
 * Each command is a 4-byte ASCII string stored as a 32-bit little-endian integer.
 * Example: "CNXN" = 0x4E584E43 (stored as 43 4E 58 4E in memory)
 */
const COMMANDS = {
  AUTH: commandToInt("AUTH"),  // Authentication handshake
  CNXN: commandToInt("CNXN"),  // Connection request/acknowledgment
  CLSE: commandToInt("CLSE"),  // Close stream
  OKAY: commandToInt("OKAY"),  // Stream ready / data acknowledgment
  OPEN: commandToInt("OPEN"),  // Open new stream to service
  WRTE: commandToInt("WRTE"),  // Write data to stream
};

/**
 * ADB Feature Flags
 * 
 * Sent in the CNXN packet to advertise host capabilities.
 * We use minimal features to ensure compatibility.
 * 
 * NOTE: We deliberately do NOT advertise "shell_v2" because that requires
 * implementing the shell v2 protocol with multiplexed stdin/stdout/stderr.
 * Without it, we use the simpler legacy shell protocol.
 */
const ADB_FEATURES = [
  "cmd",              // Support for cmd: service
  "stat_v2",          // Enhanced file stat information
  "ls_v2",            // Enhanced directory listing
  "fixed_push_mkdir", // Create parent directories when pushing files
];

/**
 * Convert a 4-character command string to a 32-bit little-endian integer.
 * 
 * ADB commands are 4 ASCII characters packed into a 32-bit value.
 * Example: "CNXN" → 0x4E584E43 (bytes: 43 4E 58 4E)
 * 
 * @param {string} command - 4-character command string
 * @returns {number} 32-bit integer representation
 */
function commandToInt(command) {
  return (
    command.charCodeAt(0) |        // Byte 0: first char
    (command.charCodeAt(1) << 8) | // Byte 1: second char
    (command.charCodeAt(2) << 16) | // Byte 2: third char
    (command.charCodeAt(3) << 24)  // Byte 3: fourth char
  );
}

/**
 * Convert a 32-bit integer back to a 4-character command string.
 * 
 * @param {number} value - 32-bit command value
 * @returns {string} 4-character command string
 */
function intToCommand(value) {
  return String.fromCharCode(
    value & 0xff,          // Byte 0
    (value >> 8) & 0xff,   // Byte 1
    (value >> 16) & 0xff,  // Byte 2
    (value >> 24) & 0xff   // Byte 3
  );
}

/**
 * Convert various input types to Uint8Array for transmission.
 * 
 * @param {Uint8Array|ArrayBuffer|string} value - Input data
 * @returns {Uint8Array} Binary data ready for transmission
 */
function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return textEncoder.encode(value);
  return new Uint8Array(0);
}

/**
 * Calculate ADB packet checksum.
 * 
 * The checksum is simply the sum of all payload bytes, treated as unsigned.
 * This is NOT a CRC - just a simple additive checksum.
 * 
 * @param {Uint8Array} bytes - Payload bytes
 * @returns {number} 32-bit unsigned checksum
 */
function adbChecksum(bytes) {
  let sum = 0;
  for (const byte of bytes) {
    sum = (sum + byte) >>> 0;  // >>> 0 ensures unsigned 32-bit result
  }
  return sum;
}

/**
 * Build a 24-byte ADB packet header.
 * 
 * ADB Packet Header Structure (24 bytes, all little-endian):
 * ┌─────────┬─────────┬─────────────────────────────────────────────┐
 * │ Offset  │ Size    │ Field                                       │
 * ├─────────┼─────────┼─────────────────────────────────────────────┤
 * │ 0       │ 4 bytes │ command   - Command identifier (CNXN, etc.) │
 * │ 4       │ 4 bytes │ arg0      - First argument                  │
 * │ 8       │ 4 bytes │ arg1      - Second argument                 │
 * │ 12      │ 4 bytes │ data_len  - Length of payload data          │
 * │ 16      │ 4 bytes │ data_crc  - Checksum of payload data        │
 * │ 20      │ 4 bytes │ magic     - command ^ 0xFFFFFFFF            │
 * └─────────┴─────────┴─────────────────────────────────────────────┘
 * 
 * The magic field is used for packet validation: magic = ~command
 * 
 * @param {number} command - Command as 32-bit integer
 * @param {number} arg0 - First argument (meaning depends on command)
 * @param {number} arg1 - Second argument (meaning depends on command)
 * @param {number} payloadLength - Length of payload data
 * @param {number} checksum - Checksum of payload data
 * @returns {Uint8Array} 24-byte header
 */
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

/**
 * Parse device properties from CNXN payload.
 * 
 * The CNXN payload contains the device's identity string in format:
 *   "device::prop1=value1;prop2=value2;..."
 * 
 * Common properties include:
 * - ro.product.name: Device product name
 * - ro.product.model: Device model
 * - ro.serialno: Device serial number
 * 
 * @param {string} payload - CNXN payload string
 * @returns {Object} Key-value map of device properties
 */
function parseProperties(payload) {
  const text = payload.replace(/\0/g, "");  // Remove null terminators
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

/**
 * Check if a USB alternate setting matches the ADB interface.
 * 
 * ADB uses a vendor-specific USB interface with specific class codes:
 * - Class: 0xFF (Vendor Specific)
 * - Subclass: 0x42 (ADB-specific)
 * - Protocol: 0x01 (ADB protocol version)
 * 
 * @param {USBAlternateInterface} alternate - USB alternate setting to check
 * @returns {boolean} True if this is an ADB interface
 */
function matchUsbInterface(alternate) {
  return (
    alternate.interfaceClass === 0xff &&
    alternate.interfaceSubclass === 0x42 &&
    alternate.interfaceProtocol === 0x01
  );
}

/**
 * Search a USB device's configurations for an ADB interface.
 * 
 * Iterates through all configurations, interfaces, and alternate settings
 * to find one that matches the ADB class/subclass/protocol.
 * 
 * @param {USBDevice} device - WebUSB device object
 * @returns {Object|null} Object with {configuration, interface_, alternate} or null
 */
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

/**
 * Find the bulk IN and OUT endpoints from a USB interface.
 * 
 * ADB requires two bulk endpoints:
 * - IN endpoint: Device sends data to host (e.g., command responses)
 * - OUT endpoint: Host sends data to device (e.g., commands)
 * 
 * @param {USBEndpoint[]} endpoints - Array of USB endpoints
 * @returns {Object} Object with {inEndpoint, outEndpoint}
 * @throws {Error} If both endpoints are not found
 */
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

// =============================================================================
// Base64 and BigInt Conversion Utilities
// =============================================================================
// These are used for RSA key handling and cryptographic operations.

/**
 * Convert base64url-encoded string to Uint8Array.
 * Base64url uses - instead of + and _ instead of /, with no padding.
 */
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

/**
 * Convert Uint8Array to standard base64 string.
 */
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert big-endian byte array to JavaScript BigInt.
 * Used for RSA key component manipulation.
 */
function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * Convert BigInt to little-endian byte array of specified length.
 * Android's RSAPublicKey format stores numbers in little-endian.
 */
function bigIntToLEBytes(value, length) {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i += 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/**
 * Convert BigInt to big-endian byte array of specified length.
 * Standard format for cryptographic operations.
 */
function bigIntToBEBytes(value, length) {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

// =============================================================================
// RSA Cryptographic Operations for ADB Authentication
// =============================================================================
// 
// ADB uses RSA-2048 for authentication. The host generates a key pair and
// stores it. When connecting, the host signs a device-provided token with
// its private key to prove identity.

/**
 * Modular exponentiation: (base ^ exponent) mod modulus
 * 
 * Uses the square-and-multiply algorithm for efficiency with large numbers.
 * This is the core operation for RSA encryption/decryption.
 * 
 * @param {BigInt} base - The base value
 * @param {BigInt} exponent - The exponent
 * @param {BigInt} modulus - The modulus
 * @returns {BigInt} Result of modular exponentiation
 */
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

/**
 * Calculate the modular multiplicative inverse of n0 mod 2^32.
 * 
 * This is used by Android's RSAPublicKey format for Montgomery multiplication
 * optimization. The result satisfies: (n0 * result) ≡ -1 (mod 2^32)
 * 
 * Uses the extended Euclidean algorithm.
 * 
 * @param {BigInt} n0 - The lowest 32 bits of the RSA modulus
 * @returns {number} The 32-bit modular inverse
 */
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

/**
 * Build an Android RSAPublicKey structure.
 * 
 * Android uses a custom binary format for RSA public keys, NOT the standard
 * DER/PEM format. This is required for ADB authentication.
 * 
 * Android RSAPublicKey Structure (for 2048-bit key = 524 bytes):
 * ┌─────────┬─────────┬─────────────────────────────────────────────────┐
 * │ Offset  │ Size    │ Field                                           │
 * ├─────────┼─────────┼─────────────────────────────────────────────────┤
 * │ 0       │ 4 bytes │ len       - Number of 32-bit words in modulus   │
 * │ 4       │ 4 bytes │ n0inv     - -1/n[0] mod 2^32 (Montgomery const) │
 * │ 8       │ 256 B   │ n         - Modulus (little-endian)             │
 * │ 264     │ 256 B   │ rr        - R^2 mod n (Montgomery constant)     │
 * │ 520     │ 4 bytes │ e         - Public exponent (usually 65537)     │
 * └─────────┴─────────┴─────────────────────────────────────────────────┘
 * 
 * Montgomery constants (n0inv and rr) enable fast modular multiplication
 * using Montgomery reduction algorithm.
 * 
 * @param {BigInt} n - RSA modulus
 * @param {BigInt} e - RSA public exponent
 * @param {number} bits - Key size in bits (2048)
 * @returns {Uint8Array} Android RSAPublicKey binary structure
 */
function buildAndroidRsaPublicKey(n, e, bits) {
  const modulusBytes = bits / 8;          // 256 bytes for 2048-bit key
  const n0 = n & 0xffffffffn;             // Lowest 32 bits of modulus
  const n0inv = modInverse32(n0);         // Montgomery constant
  const rr = (1n << BigInt(bits * 2)) % n; // R^2 mod n where R = 2^bits

  // Total size: 4 + 4 + 256 + 256 + 4 = 524 bytes
  const buffer = new ArrayBuffer(4 + 4 + modulusBytes + modulusBytes + 4);
  const view = new DataView(buffer);
  
  view.setUint32(0, modulusBytes / 4, true);  // Offset 0: len (64 words)
  view.setUint32(4, n0inv, true);              // Offset 4: n0inv
  
  const nLe = bigIntToLEBytes(n, modulusBytes);
  const rrLe = bigIntToLEBytes(rr, modulusBytes);
  
  new Uint8Array(buffer, 8, modulusBytes).set(nLe);               // Offset 8: n
  new Uint8Array(buffer, 8 + modulusBytes, modulusBytes).set(rrLe); // Offset 264: rr
  
  view.setUint32(8 + modulusBytes + modulusBytes, Number(e), true); // Offset 520: e
  
  return new Uint8Array(buffer);
}

/**
 * Build the public key payload for AUTH_RSAPUBLICKEY.
 * 
 * The payload is: base64(androidPublicKey) + " " + keyIdentifier + "\0"
 * Example: "AAAAB3NzaC1yc2E... adb@webusb\0"
 * 
 * @param {Object} publicJwk - Public key in JWK format
 * @returns {Uint8Array} Payload bytes for AUTH packet
 */
function buildPublicKeyPayload(publicJwk) {
  const nBytes = base64UrlToBytes(publicJwk.n);
  const eBytes = base64UrlToBytes(publicJwk.e);
  const n = bytesToBigInt(nBytes);
  const e = bytesToBigInt(eBytes);
  const pubkey = buildAndroidRsaPublicKey(n, e, 2048);
  const base64 = bytesToBase64(pubkey);
  return textEncoder.encode(`${base64} adb@webusb\0`);
}

/**
 * Sign an ADB authentication token using RSA with PKCS#1 v1.5 padding.
 * 
 * ADB Authentication Flow:
 * 1. Device sends AUTH(TOKEN) with 20-byte random token
 * 2. Host signs the token and sends AUTH(SIGNATURE) with 256-byte signature
 * 3. If device doesn't recognize the key, it sends another AUTH(TOKEN)
 * 4. Host sends AUTH(RSAPUBLICKEY) with its public key
 * 5. User approves on device, device sends CNXN
 * 
 * The signature uses PKCS#1 v1.5 padding:
 * - Padded message: 0x00 0x01 [0xFF...] 0x00 [DigestInfo] [Hash]
 * - The hash is SHA-1 of the 20-byte token (which is already a hash)
 * 
 * @param {Uint8Array} token - 20-byte token from device
 * @param {Object} privateJwk - Private key in JWK format
 * @returns {Promise<Uint8Array>} 256-byte RSA signature
 */
async function rsaSignAdbToken(token, privateJwk) {
  const nBytes = base64UrlToBytes(privateJwk.n);
  const dBytes = base64UrlToBytes(privateJwk.d);
  const n = bytesToBigInt(nBytes);
  const d = bytesToBigInt(dBytes);
  const modulusBytes = nBytes.length;  // 256 bytes for 2048-bit key

  // Hash the token if it's not already SHA-1 length (20 bytes)
  // The device sends a 20-byte random token which is already the right size
  let data = token;
  if (data.length !== SHA1_DIGEST_LENGTH) {
    const digest = await crypto.subtle.digest("SHA-1", data);
    data = new Uint8Array(digest);
  }

  /**
   * Build PKCS#1 v1.5 padded message (256 bytes for 2048-bit RSA):
   * ┌────────┬────────┬───────────────┬────────┬──────────────┬──────────┐
   * │ 0x00   │ 0x01   │ 0xFF...0xFF   │ 0x00   │ DigestInfo   │ Hash     │
   * │ 1 byte │ 1 byte │ N bytes       │ 1 byte │ 15 bytes     │ 20 bytes │
   * └────────┴────────┴───────────────┴────────┴──────────────┴──────────┘
   * Total: 256 bytes, padding fills the gap
   */
  const padded = new Uint8Array(modulusBytes);
  let index = 0;
  padded[index++] = 0x00;  // Leading zero
  padded[index++] = 0x01;  // Block type for private key operations
  
  // Fill with 0xFF bytes (padding)
  const fillLength =
    padded.length - SHA1_DIGEST_INFO.length - data.length - 1;
  while (index < fillLength) {
    padded[index++] = 0xff;
  }
  
  padded[index++] = 0x00;  // Separator
  padded.set(SHA1_DIGEST_INFO, index);  // DigestInfo (identifies SHA-1)
  index += SHA1_DIGEST_INFO.length;
  padded.set(data, index);  // The actual hash

  // RSA signature: signature = message^d mod n
  const signature = powMod(bytesToBigInt(padded), d, n);
  return bigIntToBEBytes(signature, modulusBytes);
}

// =============================================================================
// AdbUsbClient Class - Main ADB over WebUSB Implementation
// =============================================================================
/**
 * AdbUsbClient provides a complete ADB client implementation over WebUSB.
 * 
 * This class handles:
 * - USB device selection and connection
 * - ADB protocol handshake and authentication
 * - Stream multiplexing for multiple concurrent operations
 * - Shell command execution
 * - Package management operations
 * 
 * Usage Example:
 * ```javascript
 * const client = new AdbUsbClient();
 * const device = await AdbUsbClient.requestDevice();
 * client.setDevice(device);
 * await client.connect();
 * const packages = await client.listPackages();
 * ```
 */
export class AdbUsbClient {
  /**
   * Create a new ADB USB client.
   * 
   * @param {Object} options - Configuration options
   * @param {number} options.streamTimeoutMs - Timeout for stream operations (default 5000ms)
   */
  constructor({ streamTimeoutMs = 5000 } = {}) {
    // Configuration
    this.streamTimeoutMs = streamTimeoutMs;  // Timeout for opening/reading streams
    
    // USB Device State
    this.device = null;                // WebUSB device object
    this.configurationRef = null;      // USB configuration containing ADB interface
    this.interfaceRef = null;          // USB interface for ADB
    this.alternateRef = null;          // Alternate setting for ADB
    this.interfaceNumber = null;       // Interface number (typically 1)
    this.inEndpoint = null;            // Endpoint number for receiving data
    this.outEndpoint = null;           // Endpoint number for sending data
    this.inPacketSize = null;          // Max packet size for IN endpoint (typically 512)
    this.outPacketSize = null;         // Max packet size for OUT endpoint (typically 512)
    
    // ADB Protocol State
    this.readSize = 4096;              // Size of USB read buffer
    this.maxPayload = 4096;            // Max payload size for ADB packets
    this.deviceProperties = {};        // Properties from device CNXN response
    this.packetLog = [];               // Log of sent/received packets for debugging
    
    // Stream Management
    this.waiters = [];                 // Pending promise resolvers waiting for packets
    this.streams = new Map();          // Map of localId -> stream state
    this.nextLocalId = 1;              // Next local stream ID to assign
    
    // Read Loop State
    this.readLoopActive = false;       // Whether read loop should continue
    this.readLoopRunning = false;      // Whether read loop is currently executing
    
    // Authentication State
    this.keyPairPromise = null;        // Promise for RSA key pair (cached)
    this.publicKeyPayload = null;      // Pre-built public key payload
    this.authSentPublicKey = false;    // Whether we've sent our public key
    this.authSentSignature = false;    // Whether we've sent a signature
    
    // Diagnostics
    this.lastDiagnostics = null;       // Last diagnostic info for debugging
  }

  /**
   * Prompt the user to select a USB device that supports ADB.
   * 
   * Uses WebUSB's requestDevice() with a filter for the ADB interface
   * class codes. The browser shows a device picker dialog.
   * 
   * @returns {Promise<USBDevice>} Selected USB device
   * @throws {Error} If user cancels or no compatible device found
   */
  static async requestDevice() {
    const device = await navigator.usb.requestDevice({
      filters: [
        // Filter for ADB interface: Vendor class (0xFF), ADB subclass (0x42), protocol 1
        { classCode: 0xff, subclassCode: 0x42, protocolCode: 0x01 },
      ],
    });
    // Verify the device has an ADB interface
    const interfaceInfo = findUsbInterface(device);
    if (!interfaceInfo) {
      throw new Error("No ADB interface found on device.");
    }
    return { device, interfaceInfo };
  }

  /**
   * Check if a device is the same as the currently connected device.
   * Compares vendor ID, product ID, and serial number.
   */
  isSameDevice(device) {
    if (!this.device || !device) return false;
    return (
      this.device.vendorId === device.vendorId &&
      this.device.productId === device.productId &&
      (this.device.serialNumber || "") === (device.serialNumber || "")
    );
  }

  /**
   * Get diagnostic information about the current connection.
   * 
   * Useful for debugging connection issues. Returns information about:
   * - USB device identifiers (vendor/product ID, serial number)
   * - USB configuration and interface settings
   * - Endpoint numbers and packet sizes
   * - Recent packet log (last 50 packets)
   * 
   * @returns {Object} Diagnostic information
   */
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
      packetLog: this.packetLog.slice(-50),  // Last 50 packets
    };
    this.lastDiagnostics = diagnostics;
    return diagnostics;
  }

  /**
   * Get extended diagnostic information including full USB descriptor dump.
   * 
   * In addition to basic diagnostics, includes the complete USB configuration
   * hierarchy: all configurations, interfaces, alternate settings, and endpoints.
   * 
   * @returns {Object} Extended diagnostic information
   */
  getFullDiagnostics() {
    if (!this.device) return { connected: false };
    
    // Dump all USB configurations, interfaces, and endpoints
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

  /**
   * Connect to an ADB device and complete the ADB handshake.
   * 
   * Connection Sequence:
   * 1. Open the USB device
   * 2. Select the appropriate configuration
   * 3. Claim the ADB interface
   * 4. Clear any stalled endpoints
   * 5. Send CNXN packet to initiate ADB handshake
   * 6. Handle AUTH challenge/response
   * 7. Wait for device's CNXN response
   * 
   * @param {Object} deviceInfo - Optional device info from requestDevice()
   * @returns {Promise<void>} Resolves when connected
   * @throws {Error} If connection fails
   */
  async connect(deviceInfo) {
    const info = deviceInfo || (await AdbUsbClient.requestDevice());
    const device = info.device;
    let interfaceInfo = info.interfaceInfo;
    
    // Always close and reopen to ensure clean USB state
    // This helps recover from previous failed connections
    if (device.opened) {
      try {
        await device.close();
      } catch (e) {
        // Ignore close errors - device may already be closed
      }
    }
    await device.open();
    this.device = device;
    
    // Reset packet log for fresh connection attempt
    this.packetLog = [];
    try {
      // Refresh interface info after opening device
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
      
      await this.sendCnxn();
      
      // Wait for CNXN response
      const cnxn = await this.waitForPacket("CNXN", 8000);
      
      // Small delay before starting read loop to let USB settle
      await new Promise(r => setTimeout(r, 50));
      
      // Now start read loop for ongoing communication
      this.ensureReadLoop();

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

  /**
   * Claim the USB interface for exclusive access.
   * 
   * USB Interface Claiming Process:
   * 1. Select the correct USB configuration (if different)
   * 2. Claim the interface for exclusive access
   * 3. Select the alternate setting (if different)
   * 4. Get fresh endpoint references
   * 
   * The interface must be claimed before any transfers can occur.
   * Only one process can claim an interface at a time - this is why
   * running `adb` on the command line blocks WebUSB access.
   * 
   * @param {USBDevice} device - The USB device
   * @param {Object} interfaceInfo - Interface information from findUsbInterface()
   * @returns {Promise<Object>} Object with {inEndpoint, outEndpoint}
   */
  async claimInterface(device, interfaceInfo) {
    // Step 1: Select the USB configuration containing the ADB interface
    // Most Android devices use configuration 1, but we check to be safe
    if (
      device.configuration?.configurationValue !==
      interfaceInfo.configuration.configurationValue
    ) {
      await device.selectConfiguration(
        interfaceInfo.configuration.configurationValue
      );
    }
    
    // Step 2: Claim the interface for exclusive access
    // This will fail if another process (like `adb server`) has claimed it
    try {
      await device.claimInterface(interfaceInfo.interface_.interfaceNumber);
    } catch (error) {
      throw new Error(
        "Unable to claim the USB interface. Close any running adb server and reconnect the device."
      );
    }
    
    // Step 3: Select alternate interface setting if needed
    // Following ya-webadb: only call selectAlternateInterface if the setting differs
    // Calling it unnecessarily can cause "transfer error" on some devices
    const currentAlternateSetting = interfaceInfo.interface_.alternate?.alternateSetting;
    if (currentAlternateSetting !== interfaceInfo.alternate.alternateSetting) {
      await device.selectAlternateInterface(
        interfaceInfo.interface_.interfaceNumber,
        interfaceInfo.alternate.alternateSetting
      );
      // Small delay for USB state to stabilize after alternate change
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    
    // Step 4: Get fresh endpoint references from the device's current configuration
    // This ensures we have up-to-date endpoint objects after claiming
    const currentInterface = device.configuration.interfaces.find(
      (i) => i.interfaceNumber === interfaceInfo.interface_.interfaceNumber
    );
    if (currentInterface) {
      const currentAlternate = currentInterface.alternates.find(
        (a) => a.alternateSetting === interfaceInfo.alternate.alternateSetting
      );
      if (currentAlternate) {
        return findUsbEndpoints(currentAlternate.endpoints);
      }
    }
    return findUsbEndpoints(interfaceInfo.alternate.endpoints);
  }

  /**
   * Disconnect from the device and clean up resources.
   * 
   * Cleanup steps:
   * 1. Stop the read loop
   * 2. Reject any pending waiters
   * 3. Clear stream state
   * 4. Release the USB interface
   * 5. Close the USB device
   */
  async disconnect() {
    this.readLoopActive = false;
    
    // Reject all pending packet waiters
    this.waiters.forEach((waiter) => waiter.reject(new Error("Disconnected")));
    this.waiters = [];
    this.streams.clear();

    if (this.device) {
      try {
        await this.device.releaseInterface(this.interfaceNumber);
      } catch (error) {
        // Ignore - interface may already be released
      }
      try {
        await this.device.close();
      } catch (error) {
        // Ignore - device may already be closed
      }
    }
    this.device = null;
  }

  // ===========================================================================
  // Package Management Methods
  // ===========================================================================
  // These methods use Android's Package Manager (pm) via shell commands.

  /**
   * List all installed packages on the device.
   * 
   * Uses: pm list packages
   * 
   * @returns {Promise<string[]>} Sorted array of package names
   */
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

  /**
   * List all disabled packages on the device.
   * 
   * Uses: pm list packages -d (the -d flag filters to disabled packages)
   * 
   * @returns {Promise<Set<string>>} Set of disabled package names
   */
  async listDisabledPackages() {
    const output = await this.runShell("pm list packages -d");
    return new Set(
      output
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.startsWith("package:"))
        .map((line) => line.replace("package:", ""))
        .filter(Boolean)
    );
  }

  /**
   * Execute a shell command on the device and return the output.
   * 
   * Opens a stream to the "shell:" service, runs the command,
   * and collects all output until the stream closes.
   * 
   * @param {string} command - Shell command to execute
   * @returns {Promise<string>} Command output
   */
  async runShell(command) {
    console.log(`[ADB] runShell: opening shell:${command}`);
    const stream = await this.openStream(`shell:${command}`);
    console.log(`[ADB] runShell: stream opened, collecting output...`);
    return this.collectStream(stream, this.streamTimeoutMs);
  }
  
  /**
   * Test shell connectivity with a simple echo command.
   * Useful for debugging connection issues.
   */
  async testShell() {
    console.log("[ADB] testShell: trying echo command");
    try {
      const result = await this.runShell("echo hello");
      console.log("[ADB] testShell result:", result);
      return result;
    } catch (e) {
      console.log("[ADB] testShell error:", e.message);
      throw e;
    }
  }

  /**
   * Disable a package for the current user (user 0).
   * 
   * Uses: pm disable-user --user 0 <package>
   * The package remains installed but becomes unavailable.
   * 
   * @param {string} packageName - Package to disable
   * @returns {Promise<string>} Command output
   */
  disablePackage(packageName) {
    return this.runShell(`pm disable-user --user 0 ${packageName}`);
  }

  /**
   * Enable a previously disabled package.
   * 
   * Uses: pm enable <package>
   * 
   * @param {string} packageName - Package to enable
   * @returns {Promise<string>} Command output
   */
  enablePackage(packageName) {
    return this.runShell(`pm enable ${packageName}`);
  }

  /**
   * Uninstall a package for the current user (user 0).
   * 
   * Uses: pm uninstall --user 0 <package>
   * Note: System packages can only be uninstalled for specific users,
   * not completely removed without root access.
   * 
   * @param {string} packageName - Package to uninstall
   * @returns {Promise<string>} Command output
   */
  uninstallPackage(packageName) {
    return this.runShell(`pm uninstall --user 0 ${packageName}`);
  }

  // ===========================================================================
  // ADB Protocol Methods
  // ===========================================================================

  /**
   * Send the initial CNXN (connection) packet to the device.
   * 
   * CNXN Packet Structure:
   * - arg0: Protocol version (0x01000001 = version 1.0.0.1)
   * - arg1: Maximum payload size the host can accept
   * - payload: Host identity string "host::features=feat1,feat2,..."
   * 
   * The device will respond with either:
   * - AUTH packet: Requires authentication
   * - CNXN packet: Connection accepted (rare, for already-authorized hosts)
   */
  async sendCnxn() {
    const version = 0x01000001;  // ADB protocol version 1.0.0.1
    const maxPayload = 1024 * 1024;  // 1MB max payload
    const features = `host::features=${ADB_FEATURES.join(",")}`;
    await this.sendPacket("CNXN", version, maxPayload, features);
  }

  /**
   * Open a stream to an ADB service.
   * 
   * ADB services are accessed by opening streams to named endpoints:
   * - "shell:command" - Run a shell command
   * - "sync:" - File sync protocol
   * - "tcp:port" - Forward TCP connection
   * - etc.
   * 
   * Stream Opening Protocol:
   * 1. Host sends OPEN packet with local-id and service name
   *    - arg0: local-id (assigned by host, used to identify this stream)
   *    - arg1: 0 (unused)
   *    - payload: service name (null-terminated string)
   * 
   * 2. Device responds with either:
   *    - OKAY: Stream opened successfully
   *      - arg0: remote-id (assigned by device)
   *      - arg1: local-id (echoed back)
   *    - CLSE: Stream rejected (service not found, etc.)
   * 
   * @param {string} service - Service name (e.g., "shell:ls")
   * @returns {Promise<Object>} Stream object for reading data
   */
  async openStream(service) {
    // Ensure read loop is running before opening stream
    // The read loop must be active to receive the OKAY response
    if (!this.readLoopRunning && this.device && this.device.opened) {
      console.log(`[ADB] openStream: restarting read loop`);
      this.ensureReadLoop();
      await new Promise(r => setTimeout(r, 50)); // Give it time to start
    }
    
    // Assign a unique local ID for this stream
    const localId = this.nextLocalId++;
    console.log(`[ADB] openStream: creating stream ${localId} for ${service}`);
    
    // Create stream state object
    const stream = {
      localId,           // Our ID for this stream
      remoteId: null,    // Device's ID (set when OKAY received)
      chunks: [],        // Received data chunks
      closed: false,     // Whether stream has been closed
      closeResolvers: [], // Callbacks to invoke when stream closes
    };
    
    // Create promise that resolves when device sends OKAY
    stream.ready = new Promise((resolve, reject) => {
      stream.readyResolve = resolve;
      stream.readyReject = reject;
      stream.readyTimeout = setTimeout(() => {
        console.log(`[ADB] openStream: timeout for ${service}`);
        reject(new Error(`Stream open timeout for ${service}`));
      }, 5000);
    });
    
    // Register stream before sending OPEN
    this.streams.set(localId, stream);
    
    // Send OPEN packet
    console.log(`[ADB] openStream: sending OPEN for stream ${localId}`);
    await this.sendPacket("OPEN", localId, 0, `${service}\0`);
    console.log(`[ADB] openStream: OPEN sent, waiting for OKAY...`);
    
    // Wait for OKAY response
    await stream.ready;
    console.log(`[ADB] openStream: got OKAY, stream ready`);
    clearTimeout(stream.readyTimeout);
    return stream;
  }

  /**
   * Collect all data from a stream until it closes or times out.
   * 
   * @param {Object} stream - Stream object from openStream()
   * @param {number} timeoutMs - Maximum time to wait
   * @returns {Promise<string>} Decoded stream output
   */
  collectStream(stream, timeoutMs) {
    return new Promise((resolve) => {
      // Set up timeout
      const timer = setTimeout(() => {
        resolve(this.decodeStream(stream));
      }, timeoutMs);
      
      // Also resolve when stream closes
      stream.closeResolvers.push(() => {
        clearTimeout(timer);
        resolve(this.decodeStream(stream));
      });
    });
  }

  /**
   * Decode stream chunks into a string.
   * Concatenates all received chunks and decodes as UTF-8.
   */
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

  /**
   * Send an ADB packet to the device.
   * 
   * Packet Structure:
   * ┌────────────────────────────────────────────────────────────┐
   * │ Header (24 bytes) │ Payload (variable length)             │
   * └────────────────────────────────────────────────────────────┘
   * 
   * The header and payload are sent as separate USB transfers.
   * A Zero-Length Packet (ZLP) is sent after data that's an exact
   * multiple of the endpoint's packet size (typically 512 bytes).
   * 
   * @param {string} command - Command name (CNXN, OPEN, WRTE, etc.)
   * @param {number} arg0 - First argument
   * @param {number} arg1 - Second argument
   * @param {Uint8Array|string} payload - Packet payload
   */
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
    
    // Log packet for debugging
    this.logPacket("out", commandValue, arg0, arg1, payloadBytes);

    const packetSize = this.outPacketSize || 0;
    
    /**
     * Send a chunk of data, handling ZLP (Zero-Length Packet) requirements.
     * 
     * USB bulk transfers use ZLP to signal end of transfer when the data
     * length is an exact multiple of the endpoint's max packet size.
     * Without ZLP, the device waits for more data indefinitely.
     */
    const sendChunk = async (chunk) => {
      // Create a copy of the chunk to avoid issues with detached buffers
      const safeChunk = chunk.length
        ? new Uint8Array(
            chunk.buffer.slice(
              chunk.byteOffset,
              chunk.byteOffset + chunk.byteLength
            )
          )
        : chunk;
      
      await this.device.transferOut(this.outEndpoint, safeChunk);
      
      // Send ZLP if chunk size is exact multiple of packet size
      if (packetSize && chunk.length && chunk.length % packetSize === 0) {
        await this.device.transferOut(this.outEndpoint, new Uint8Array(0));
      }
    };

    try {
      // Send header first, then payload
      await sendChunk(header);
      if (payloadBytes.length) {
        await sendChunk(payloadBytes);
      }
    } catch (error) {
      // Handle device disconnection
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
        // Add helpful message for transfer errors
        const message = error.message || "";
        if (message.includes("transfer error")) {
          const betterError = new Error(
            `${message} Disconnect the USB cable from the device and reconnect, or try selecting the device again.`
          );
          betterError.cause = error;
          throw betterError;
        }
        throw error;
      }
    }
  }

  /**
   * Wait for a specific packet type during connection handshake.
   * 
   * This is used during the connection phase before the read loop starts.
   * It reads packets synchronously and handles AUTH packets inline.
   * 
   * @param {string} expectedCommand - Command to wait for (e.g., "CNXN")
   * @param {number} timeoutMs - Maximum wait time
   * @returns {Promise<Object>} The received packet
   * @throws {Error} If timeout expires
   */
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
      
      // Handle AUTH packets inline during handshake
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

  /**
   * Start the background read loop if not already running.
   * 
   * The read loop continuously reads packets from the device and
   * dispatches them to the appropriate handlers (stream data, etc.).
   */
  ensureReadLoop() {
    if (this.readLoopRunning) return;
    this.readLoopActive = true;
    // Clear halt before restarting to avoid stale errors
    this.clearHaltSafe("in").then(() => {
      this.startReadLoop();
    });
  }

  /**
   * Background read loop for receiving packets from the device.
   * 
   * This runs continuously after connection is established, reading
   * packets and dispatching them to appropriate handlers:
   * - OKAY: Stream opened successfully
   * - WRTE: Data received on a stream
   * - CLSE: Stream closed
   * 
   * The loop includes error recovery for transient USB errors,
   * retrying up to 3 times before giving up.
   */
  async startReadLoop() {
    this.readLoopRunning = true;
    console.log("[ADB] Read loop started");
    let consecutiveErrors = 0;
    
    while (this.readLoopActive && this.device) {
      try {
        const packet = await this.readPacket();
        consecutiveErrors = 0; // Reset error count on success
        
        if (!packet) {
          continue;  // Timeout or invalid packet, try again
        }
        
        console.log("[ADB] Read loop: got packet:", packet.command, "arg0:", packet.arg0, "arg1:", packet.arg1);
        this.logPacket(
          "in",
          commandToInt(packet.command),
          packet.arg0,
          packet.arg1,
          packet.payload
        );
        
        // Dispatch packet to appropriate handler
        this.dispatchPacket(packet);
        
      } catch (error) {
        console.log("[ADB] Read loop error:", error.message);
        consecutiveErrors++;
        
        // Try to recover from transient errors
        if (consecutiveErrors < 3 && this.device && this.device.opened) {
          console.log("[ADB] Read loop: waiting and retrying...");
          await new Promise(r => setTimeout(r, 200));
          continue;
        }
        
        // Too many errors, stop the loop
        if (this.readLoopActive) {
          this.readLoopActive = false;
        }
        break;
      }
    }
    console.log("[ADB] Read loop ended, active=", this.readLoopActive);
    this.readLoopRunning = false;
  }

  /**
   * Read a single ADB packet from the device.
   * 
   * Packet Reading Process:
   * 1. Read header (24 bytes) from IN endpoint
   * 2. Parse header fields (see buildHeader for structure)
   * 3. Validate magic value (must equal command XOR 0xFFFFFFFF)
   * 4. If payload length > 0, read payload bytes
   * 5. Return parsed packet object
   * 
   * Header Parsing (offsets into 24-byte buffer):
   * ┌─────────┬─────────┬────────────────────────────────────────┐
   * │ Offset  │ Size    │ Field                                  │
   * ├─────────┼─────────┼────────────────────────────────────────┤
   * │ 0       │ 4 bytes │ command (e.g., 0x4E584E43 = "CNXN")    │
   * │ 4       │ 4 bytes │ arg0                                   │
   * │ 8       │ 4 bytes │ arg1                                   │
   * │ 12      │ 4 bytes │ data length                            │
   * │ 16      │ 4 bytes │ data checksum                          │
   * │ 20      │ 4 bytes │ magic (= command XOR 0xFFFFFFFF)       │
   * └─────────┴─────────┴────────────────────────────────────────┘
   * 
   * @returns {Promise<Object|undefined>} Parsed packet or undefined on timeout
   */
  async readPacket() {
    const packetSize = this.inPacketSize || 512;
    const startTime = Date.now();
    
    while (true) {
      // Timeout protection - don't hang forever
      if (Date.now() - startTime > 10000) {
        return undefined;
      }
      
      // Read from IN endpoint (device → host)
      let headerResult;
      try {
        headerResult = await this.device.transferIn(
          this.inEndpoint,
          packetSize
        );
      } catch (error) {
        throw error;
      }
      
      if (!headerResult || !headerResult.data) {
        return undefined;
      }
      
      // Header must be exactly 24 bytes
      if (headerResult.data.byteLength !== 24) {
        continue;  // Skip malformed data
      }
      
      // Parse header fields using DataView for endianness control
      const buffer = new Uint8Array(headerResult.data.buffer);
      const headerView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      
      const command = headerView.getUint32(0, true);  // Offset 0: command
      const arg0 = headerView.getUint32(4, true);     // Offset 4: arg0
      const arg1 = headerView.getUint32(8, true);     // Offset 8: arg1
      const length = headerView.getUint32(12, true);  // Offset 12: payload length
      // Offset 16: checksum (we don't verify it)
      const magic = headerView.getUint32(20, true);   // Offset 20: magic
      
      // Validate magic field
      // JavaScript's XOR produces a signed 32-bit result, but DataView returns unsigned
      // Use >>> 0 to convert to unsigned for comparison
      const expectedMagic = ((command ^ 0xffffffff) >>> 0);
      if (magic !== expectedMagic) {
        continue;  // Skip invalid packets
      }
      
      // Read payload if present
      let payload;
      if (length !== 0) {
        const payloadResult = await this.device.transferIn(
          this.inEndpoint,
          length
        );
        if (!payloadResult || !payloadResult.data) {
          return undefined;
        }
        payload = new Uint8Array(payloadResult.data.buffer);
      } else {
        payload = new Uint8Array(0);
      }
      
      return {
        command: intToCommand(command),
        arg0,
        arg1,
        payload,
      };
    }
  }

  /**
   * Dispatch a received packet to the appropriate handler.
   * 
   * Packet routing:
   * - Check waiters first (promises waiting for specific packets)
   * - OKAY: Stream opened successfully, resolve stream.ready promise
   * - WRTE: Data received on stream, add to chunks and send OKAY ack
   * - CLSE: Stream closed, invoke close resolvers
   * 
   * @param {Object} packet - Parsed packet from readPacket()
   */
  dispatchPacket(packet) {
    // Check if any waiter is waiting for this packet
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

    /**
     * Handle OKAY packet - stream opened or data acknowledged
     * 
     * When opening a stream:
     * - arg0: remote-id (device's ID for this stream)
     * - arg1: local-id (our ID, echoed back)
     */
    if (packet.command === "OKAY") {
      const localId = packet.arg1;
      const stream = this.streams.get(localId);
      if (stream && !stream.remoteId) {
        stream.remoteId = packet.arg0;
        stream.readyResolve();
      }
      return;
    }

    /**
     * Handle WRTE packet - data received on stream
     * 
     * - arg0: remote-id (sender's stream ID)
     * - arg1: local-id (our stream ID)
     * - payload: data bytes
     * 
     * We must send OKAY to acknowledge receipt.
     */
    if (packet.command === "WRTE") {
      const localId = packet.arg1;
      const stream = this.streams.get(localId);
      if (stream) {
        stream.chunks.push(packet.payload);
        this.sendPacket("OKAY", stream.localId, packet.arg0, new Uint8Array());
      }
      return;
    }

    /**
     * Handle CLSE packet - stream closed by device
     * 
     * - arg0: remote-id (0 if stream was never opened)
     * - arg1: local-id (our stream ID)
     * 
     * If remoteId is 0, the device rejected the stream open request.
     * Otherwise, it's a normal stream close.
     */
    if (packet.command === "CLSE") {
      const localId = packet.arg1;
      const remoteId = packet.arg0;
      console.log(`[ADB] CLSE received for localId=${localId}, remoteId=${remoteId}`);
      const stream = this.streams.get(localId);
      if (stream && !stream.closed) {
        stream.closed = true;
        
        // If stream was never opened (no remoteId), reject the ready promise
        // This happens when the device rejects the service (e.g., unknown service)
        if (!stream.remoteId && stream.readyReject) {
          clearTimeout(stream.readyTimeout);
          stream.readyReject(new Error(`Stream rejected by device (CLSE with remoteId=${remoteId})`));
        }
        
        // Send CLSE acknowledgment back to device
        if (remoteId) {
          this.sendPacket("CLSE", stream.localId, remoteId, new Uint8Array());
        }
        
        // Notify anyone waiting for stream to close
        stream.closeResolvers.forEach((resolve) => resolve());
      }
    }
  }

  /**
   * Register a waiter for a specific packet type.
   * Used internally for request/response patterns.
   * 
   * @param {Function} predicate - Function to match desired packet
   * @param {number} timeoutMs - Maximum wait time
   * @returns {Promise<Object>} Matching packet
   */
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

  // ===========================================================================
  // Authentication Methods
  // ===========================================================================

  /**
   * Handle AUTH packet from device during connection handshake.
   * 
   * ADB Authentication Flow:
   * ┌─────────────┐                              ┌─────────────┐
   * │    Host     │                              │   Device    │
   * └──────┬──────┘                              └──────┬──────┘
   *        │  CNXN (version, maxPayload, identity)       │
   *        │ ────────────────────────────────────────────>│
   *        │                                             │
   *        │  AUTH (TOKEN, 20-byte random token)         │
   *        │ <────────────────────────────────────────────│
   *        │                                             │
   *        │  AUTH (SIGNATURE, RSA signature of token)   │
   *        │ ────────────────────────────────────────────>│
   *        │                                             │
   *        │  If key not recognized...                   │
   *        │  AUTH (TOKEN, new 20-byte token)            │
   *        │ <────────────────────────────────────────────│
   *        │                                             │
   *        │  AUTH (RSAPUBLICKEY, public key)            │
   *        │ ────────────────────────────────────────────>│
   *        │                                             │
   *        │  User approves on device screen...          │
   *        │                                             │
   *        │  CNXN (version, maxPayload, identity)       │
   *        │ <────────────────────────────────────────────│
   *        │                                             │
   *        │  Connection established!                    │
   * 
   * @param {Object} message - AUTH packet from device
   */
  async handleAuth(message) {
    // Only handle TOKEN type AUTH packets
    if (message.arg0 !== AUTH_TOKEN) {
      return;
    }
    
    if (!crypto || !crypto.subtle) {
      throw new Error("WebCrypto not available for ADB auth.");
    }
    
    // Get or create our RSA key pair
    const { privateKey, publicKeyPayload } = await this.getOrCreateKeyPair();
    this.publicKeyPayload = publicKeyPayload;

    // First attempt: Send signature of the token
    // If the device recognizes our key, it will send CNXN
    if (!this.authSentSignature) {
      const signature = await rsaSignAdbToken(message.payload, privateKey);
      await this.sendPacket("AUTH", AUTH_SIGNATURE, 0, signature);
      this.authSentSignature = true;
      return;
    }

    // Second attempt: Send our public key
    // Device will prompt user to approve this new key
    if (!this.authSentPublicKey && this.publicKeyPayload) {
      await this.sendPacket("AUTH", AUTH_RSAPUBLICKEY, 0, this.publicKeyPayload);
      this.authSentPublicKey = true;
      return;
    }

    // If we get here, device rejected both signature and public key
    throw new Error("ADB authentication rejected by device.");
  }

  /**
   * Get or create the RSA key pair for ADB authentication.
   * 
   * Keys are stored in localStorage and reused across sessions.
   * This way, once a user approves the key on their device,
   * future connections are automatic.
   * 
   * Key Generation:
   * - Algorithm: RSA-2048
   * - Public exponent: 65537 (0x010001)
   * - Hash: SHA-1 (required for ADB compatibility)
   * 
   * @returns {Promise<Object>} Object with privateKey (JWK) and publicKeyPayload
   */
  async getOrCreateKeyPair() {
    // Return cached promise if already loading/loaded
    if (this.keyPairPromise) {
      return this.keyPairPromise;
    }
    
    this.keyPairPromise = (async () => {
      // Try to load existing key from localStorage
      const stored = localStorage.getItem(KEY_STORAGE);
      if (stored) {
        const { privateJwk, publicJwk } = JSON.parse(stored);
        const publicKeyPayload = buildPublicKeyPayload(publicJwk);
        return { privateKey: privateJwk, publicKeyPayload };
      }

      // Generate new RSA key pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,              // 2048-bit RSA
          publicExponent: new Uint8Array([1, 0, 1]),  // 65537
          hash: "SHA-1",                    // Required for ADB
        },
        true,                               // Extractable (for export)
        ["sign", "verify"]
      );
      
      // Export keys as JWK for storage
      const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      
      // Store for future sessions
      localStorage.setItem(KEY_STORAGE, JSON.stringify({ privateJwk, publicJwk }));
      
      const publicKeyPayload = buildPublicKeyPayload(publicJwk);
      return { privateKey: privateJwk, publicKeyPayload };
    })();

    return this.keyPairPromise;
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /**
   * Reset session state for a new connection.
   * Clears all pending waiters and streams without disconnecting.
   */
  resetSessionState() {
    this.waiters.forEach((waiter) => waiter.reject(new Error("ADB session reset")));
    this.waiters = [];
    this.streams.clear();
    this.nextLocalId = 1;
  }

  /**
   * Clear a stalled endpoint safely (ignoring errors).
   * 
   * USB endpoints can enter a "halted" state after errors.
   * clearHalt() resets the endpoint so transfers can continue.
   * This is called:
   * - At connection start to clear any previous state
   * - After transfer errors to attempt recovery
   * 
   * @param {string} direction - "in" or "out"
   */
  async clearHaltSafe(direction) {
    if (!this.device) return;
    const endpoint = direction === "in" ? this.inEndpoint : this.outEndpoint;
    if (endpoint == null) return;
    try {
      await this.device.clearHalt(direction, endpoint);
    } catch (error) {
      // Ignore - endpoint may not be halted
    }
  }

  /**
   * Log a packet for debugging/diagnostics.
   * 
   * Maintains a circular buffer of the last 200 packets.
   * Useful for debugging connection issues.
   * 
   * @param {string} direction - "in" (received) or "out" (sent)
   * @param {number|string} commandValue - Command as int or string
   * @param {number} arg0 - First argument
   * @param {number} arg1 - Second argument
   * @param {Uint8Array} payload - Packet payload
   */
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
    
    // Keep only last 200 packets
    if (this.packetLog.length > 200) {
      this.packetLog.splice(0, this.packetLog.length - 200);
    }
  }
}

// =============================================================================
// END OF ADB OVER WEBUSB IMPLEMENTATION
// =============================================================================
