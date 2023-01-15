import * as secp256k1 from '@transmute/did-key-secp256k1';
import { Resolver } from 'did-resolver';
import { TDIDdoc } from './types';
export declare const DIDResolver: Resolver;
export declare enum SERVICE_TYPES {
    WMS = "carbon3 wms",
    PARTNER = "carbon3 partner"
}
export declare function createDID(): Promise<TDIDdoc>;
export declare function adjustDID(didweb: string, did: TDIDdoc): TDIDdoc;
export declare function createDIDKeypair(): Promise<secp256k1.Secp256k1KeyPair>;
//# sourceMappingURL=dids.d.ts.map