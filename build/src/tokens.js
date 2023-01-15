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
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyVC = exports.createRevocationToken = exports.createToken = exports.CredentialStatus = void 0;
const secp256k1 = __importStar(require("@transmute/did-key-secp256k1"));
const did_jwt_vc_1 = require("did-jwt-vc");
const did_jwt_1 = require("did-jwt");
var CredentialStatus;
(function (CredentialStatus) {
    CredentialStatus["ACTIVE"] = "ACTIVE";
    CredentialStatus["REVOKED"] = "REVOKED";
})(CredentialStatus = exports.CredentialStatus || (exports.CredentialStatus = {}));
async function createVC(input) {
    const { issuerDID, toDID, id, type, credentialSubject } = input;
    const issuerKey = await secp256k1.Secp256k1KeyPair.from(issuerDID.keys[0]);
    if (!issuerKey.privateKey)
        throw new Error('issuerKey.privateKey missing');
    const signer = (0, did_jwt_1.ES256KSigner)(issuerKey.privateKey);
    const issuer = { did: issuerDID.didDocument.id, signer };
    const cred = {
        id,
        iss: issuerKey.controller,
        sub: toDID,
        nbf: Math.floor(new Date().getTime() / 1000),
        vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
            type,
            issuer: {
                id: issuerKey.controller,
            },
            credentialSubject,
        },
    };
    const vcJwt = await (0, did_jwt_vc_1.createVerifiableCredentialJwt)(cred, issuer);
    return { vc: vcJwt, payload: cred };
}
async function createToken(input) {
    const { issuerDID, toDID, internalID, amountCO2e, reference } = input;
    return createVC({
        issuerDID,
        toDID,
        id: internalID,
        type: ['VerifiableCredential', 'Carbon3Token'],
        credentialSubject: { amountCO2e, reference, status: CredentialStatus.ACTIVE },
    });
}
exports.createToken = createToken;
async function createRevocationToken(input) {
    const { issuerDID, toDID, internalID, activeVCid, amountCO2e, reference } = input;
    return createVC({
        issuerDID,
        toDID,
        id: internalID,
        type: ['VerifiableCredential', 'Carbon3Token'],
        credentialSubject: {
            revokedVCid: activeVCid,
            amountCO2e,
            reference,
            status: CredentialStatus.REVOKED,
        },
    });
}
exports.createRevocationToken = createRevocationToken;
async function verifyVC(vc, issuerDIDdoc) {
    function resolver(diddoc) {
        return {
            resolve: async () => {
                return {
                    didResolutionMetadata: [],
                    didDocumentMetadata: [],
                    didDocument: diddoc,
                };
            },
        };
    }
    return await (0, did_jwt_vc_1.verifyCredential)(vc, resolver(issuerDIDdoc));
}
exports.verifyVC = verifyVC;
//# sourceMappingURL=tokens.js.map