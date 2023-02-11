import crypto from 'crypto';
import * as ed25519 from '@transmute/did-key-ed25519';
import { Resolver } from 'did-resolver';
import webResolver from 'web-did-resolver';
import { TDIDdoc } from './types';

export const DIDResolver = new Resolver({
  ...webResolver.getResolver(),
});

export enum SERVICE_TYPES {
  WMS = 'carbon3 wms',
  PARTNER = 'carbon3 partner',
}

export async function createDID(): Promise<TDIDdoc> {
  const doc = await ed25519.generate({
    secureRandom: () => {
      return crypto.randomBytes(32);
    },
  });
  return doc;
}

// helper function to replace all did:key by did:web in the diddoc
export function adjustDID(didweb: string, did: TDIDdoc) {
  let str = JSON.stringify(did);
  str = str.replaceAll('"' + did.didDocument.id, '"' + didweb);
  return JSON.parse(str) as TDIDdoc;
}

export async function createDIDKeypair(): Promise<ed25519.Ed25519KeyPair> {
  return ed25519.Ed25519KeyPair.generate({
    secureRandom: () => {
      return crypto.randomBytes(32);
    },
  });
}
