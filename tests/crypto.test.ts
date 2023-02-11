import { createVC, verifyVC } from '../src/tokens';
import { adjustDID, createDID } from '../src/dids';

describe('Cryptography', () => {
  it('Basic DIDdoc checks', async () => {
    const doc = await createDID();

    expect(doc.keys).toHaveLength(1);
    expect(doc.didDocument.id.length).toBeGreaterThan(0);
  });

  it('Basic DIDdoc checks', async () => {
    const didweb = 'did:web:fake';
    const doc = await createDID();
    const docX = await adjustDID(didweb, doc);

    expect(docX.didDocument.id.startsWith(didweb)).toBeTruthy();
    expect(docX.keys[0].id.startsWith(didweb)).toBeTruthy();
  });

  it('Basic VCs', async () => {
    const didFrom = await createDID();
    const didTo = await createDID();

    const vc = await createVC({
      issuerDID: didFrom,
      toDID: didTo.keys[0].id.split('#')[0],
      credentialSubject: { this: 'is a test' },
      id: '123',
      type: ['VerifiableCredential', 'TestToken'],
    });

    const verif = await verifyVC(vc.vc, didFrom.didDocument);

    expect(verif.verified).toBeTruthy();
    expect(vc.payload.iss).toEqual(didFrom.didDocument.id);
    expect(vc.payload.sub).toEqual(didTo.didDocument.id);
  });
});
