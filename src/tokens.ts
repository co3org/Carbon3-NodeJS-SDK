import * as secp256k1 from '@transmute/did-key-secp256k1';
import { JwtCredentialPayload, createVerifiableCredentialJwt, verifyCredential, Issuer } from 'did-jwt-vc';
import { ES256KSigner } from 'did-jwt';
import { DIDDocument, DIDResolutionResult } from 'did-resolver';
import { JWT } from 'did-jwt-vc/lib/types';
import { TDIDdoc } from './types';

export enum CredentialStatus {
  ACTIVE = 'ACTIVE',
  REVOKED = 'REVOKED',
}

export async function createVC(input: {
  issuerDID: TDIDdoc;
  toDID: string;
  id: string;
  type: string[];
  credentialSubject: { [key: string]: any };
}): Promise<{ vc: JWT; payload: JwtCredentialPayload }> {
  const { issuerDID, toDID, id, type, credentialSubject } = input;
  const issuerKey = await secp256k1.Secp256k1KeyPair.from(issuerDID.keys[0]);
  if (!issuerKey.privateKey) throw new Error('issuerKey.privateKey missing');

  const signer = ES256KSigner(issuerKey.privateKey);
  const issuer: Issuer = { did: issuerDID.didDocument.id, signer };
  const cred: JwtCredentialPayload = {
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

  const vcJwt = await createVerifiableCredentialJwt(cred, issuer);
  return { vc: vcJwt, payload: cred };
}

export async function createToken(input: {
  issuerDID: TDIDdoc;
  toDID: string;
  internalID: string;
  amountCO2e: number;
  reference: string;
}): Promise<{ vc: JWT; payload: JwtCredentialPayload }> {
  const { issuerDID, toDID, internalID, amountCO2e, reference } = input;

  return createVC({
    issuerDID,
    toDID,
    id: internalID,
    type: ['VerifiableCredential', 'Carbon3Token'],
    credentialSubject: { amountCO2e, reference, status: CredentialStatus.ACTIVE },
  });
}

export async function createRevocationToken(input: {
  issuerDID: TDIDdoc;
  toDID: string;
  internalID: string;
  activeVCid: string;
  amountCO2e: number;
  reference: string;
}): Promise<{ vc: JWT; payload: JwtCredentialPayload }> {
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

export async function verifyVC(vc: JWT, issuerDIDdoc: DIDDocument) {
  function resolver(diddoc: DIDDocument) {
    return {
      resolve: async (): Promise<DIDResolutionResult> => {
        return {
          didResolutionMetadata: [],
          didDocumentMetadata: [],
          didDocument: diddoc,
        };
      },
    };
  }

  return await verifyCredential(vc, resolver(issuerDIDdoc));
}
