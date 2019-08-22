const {babyJub} = require("circomlib");
const {createHmac} = require("crypto");
const {toBufferBE, toBigIntBE} = require("bigint-buffer");
const assert = require("assert");
const {mnemonicToSeedSync} = require("bip39");

/**
 * 
 * @typedef {Array} Point
 */

/**
 * 
 * @typedef {Object} Pubkey
 * @property {Point} K
 * @property {Buffer} c
 */

/**
 * 
 * @typedef {Object} Privkey
 * @property {BigInt} k
 * @property {Buffer} c
 */


/**
 * 
 * @param {Buffer|String} key 
 * @param {Buffer|String} data 
 * @returns {Buffer}
 */

function hmacsha512(key, data) {
  const hmac = createHmac("sha512", key);
  hmac.update(data);
  return hmac.digest();
}

/**
 * 
 * @param {BigInt} p
 * @returns {Point}
 */
function point(p) {
  return babyJub.mulPointEscalar(babyJub.Base8, p);
}

/**
 * 
 * @param {number} i 
 * @returns {Buffer}
 */

function ser32(i) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(i);
  return b;
}



/**
 * 
 * @param {BigInt} i 
 * @returns {Buffer}
 */

function ser256(i) {
  return toBufferBE(i, 32);
}

/**
 * 
 * @param {Point} P
 * @returns {Buffer} 
 */
function serp(P) {
  return babyJub.packPoint(P);
}

/**
 * 
 * @param {Buffer} p
 * @returns {BigInt} 
 */
function parse256(p) {
  return toBigIntBE(p);
}

/**
 * 
 * @param {Privkey}
 * @param {number} i 
 * @returns {Privkey}
 */

function CKDPriv({k, c}, i) {
  const L = hmacsha512(c, Buffer.concat([(i>=0x80000000) ? ser256(k) : serp(point(k)), ser32(i)]));
  const ki = (k + parse256(L.slice(0,32))) % babyJub.subOrder;
  const ci = L.slice(32, 64);
  return {k:ki, c:ci};
} 

/**
 * 
 * @param {Pubkey}
 * @param {number} i 
 * @returns {Pubkey}
 */

function CKDPub({K, c}, i) {
  assert(i<0x80000000, "Cannot compute hardended child from public key");
  const L = hmacsha512(c, Buffer.concat([serp(K), ser32(i)]));
  const Ki = babyJub.addPoint(K, point(parse256(L.slice(0,32))));
  const ci = L.slice(32, 64);
  return {K:Ki, c:ci};
}

/**
 * 
 * @param {Buffer} S 
 * @returns {Privkey}
 */

function MasterKey(S) {
  const L = hmacsha512("BabyJub seed", S);
  const k = parse256(L.slice(0,32)) % babyJub.subOrder;
  const c = L.slice(32, 64);
  return {k, c};
}

function parseIndexes(path) {
  const steps = path.split('/');
  assert(steps[0] == "m", "Wrong path: path must be beginning from 'm'");
  const indexes = steps.slice(1).map(step => parseInt(step) + (step.slice(-1) === '\'') ? 0x80000000 : 0);
  assert(!indexes.includes(NaN), "Wrong path: not a number inside the path");
  return indexes;
}


function Privkey(mnemonic, path) {
  const seed = mnemonicToSeedSync(mnemonic);
  let res = MasterKey(seed);
  parseIndexes(path).forEach(i=>res = CKDPriv(res, i));
  return res;
}

function Pubkey(mnemonic, path) {
  const {k, c} = Privkey(mnemonic, path);
  const K = babyJub.mulPointEscalar(babyJub.Base8, k);
  return {K, c};
}

module.exports = {Privkey, Pubkey, CKDPriv, CKDPub};