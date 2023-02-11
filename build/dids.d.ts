import * as ed25519 from '@transmute/did-key-ed25519';
import { Resolver } from 'did-resolver';
import { TDIDdoc } from './types';
export declare const DIDResolver: Resolver;
export declare enum SERVICE_TYPES {
    WMS = "carbon3 wms",
    PARTNER = "carbon3 partner"
}
export declare function createDID(): Promise<TDIDdoc>;
export declare function adjustDID(didweb: string, did: TDIDdoc): TDIDdoc;
export declare function createDIDKeypair(): Promise<ed25519.Ed25519KeyPair>;
