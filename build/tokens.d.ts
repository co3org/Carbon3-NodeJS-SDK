import { JwtCredentialPayload } from 'did-jwt-vc';
import { DIDDocument } from 'did-resolver';
import { JWT } from 'did-jwt-vc/lib/types';
import { TDIDdoc } from './types';
export declare enum CredentialStatus {
    ACTIVE = "ACTIVE",
    REVOKED = "REVOKED"
}
export declare function createVC(input: {
    issuerDID: TDIDdoc;
    toDID: string;
    id: string;
    type: string[];
    credentialSubject: {
        [key: string]: any;
    };
}): Promise<{
    vc: JWT;
    payload: JwtCredentialPayload;
}>;
export declare function createToken(input: {
    issuerDID: TDIDdoc;
    toDID: string;
    internalID: string;
    amountCO2e: number;
    reference: string;
}): Promise<{
    vc: JWT;
    payload: JwtCredentialPayload;
}>;
export declare function createRevocationToken(input: {
    issuerDID: TDIDdoc;
    toDID: string;
    internalID: string;
    activeVCid: string;
    amountCO2e: number;
    reference: string;
}): Promise<{
    vc: JWT;
    payload: JwtCredentialPayload;
}>;
export declare function verifyVC(vc: JWT, issuerDIDdoc: DIDDocument): Promise<import("did-jwt-vc").VerifiedCredential>;
