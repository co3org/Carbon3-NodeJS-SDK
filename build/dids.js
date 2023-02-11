"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createDIDKeypair = exports.adjustDID = exports.createDID = exports.SERVICE_TYPES = exports.DIDResolver = void 0;
const crypto_1 = __importDefault(require("crypto"));
const ed25519 = __importStar(require("@transmute/did-key-ed25519"));
const did_resolver_1 = require("did-resolver");
const web_did_resolver_1 = __importDefault(require("web-did-resolver"));
exports.DIDResolver = new did_resolver_1.Resolver({
    ...web_did_resolver_1.default.getResolver(),
});
var SERVICE_TYPES;
(function (SERVICE_TYPES) {
    SERVICE_TYPES["WMS"] = "carbon3 wms";
    SERVICE_TYPES["PARTNER"] = "carbon3 partner";
})(SERVICE_TYPES = exports.SERVICE_TYPES || (exports.SERVICE_TYPES = {}));
async function createDID() {
    const doc = await ed25519.generate({
        secureRandom: () => {
            return crypto_1.default.randomBytes(32);
        },
    });
    return doc;
}
exports.createDID = createDID;
// helper function to replace all did:key by did:web in the diddoc
function adjustDID(didweb, did) {
    let str = JSON.stringify(did);
    str = str.replaceAll('"' + did.didDocument.id, '"' + didweb);
    return JSON.parse(str);
}
exports.adjustDID = adjustDID;
async function createDIDKeypair() {
    return ed25519.Ed25519KeyPair.generate({
        secureRandom: () => {
            return crypto_1.default.randomBytes(32);
        },
    });
}
exports.createDIDKeypair = createDIDKeypair;
//# sourceMappingURL=dids.js.map