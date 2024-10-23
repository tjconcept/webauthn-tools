# Webauthn (Web Authentication) helpers

## Exports

- `importKey()`
- `verifySignature()`
- `getChallenge()`
- `parseClientDataJSON()`
- `parseAuthenticatorData()`

## `importKey()`

Import the public key of a Passkey attestation ("sign up").

Supported COSE Algorithm Identifiers:

- `-8`
- `-7`
- `-257`

If `data` is not guaranteed to be valid, e.g. originates from a user, the
operation should be wrapped in a try-catch block.

```js
importKey({
  algorithm, // COSE Algorithm Identifier
  data, // ArrayBuffer, TypedArray, DataView, or JSONWebKey
  extractable = false
}) // → CryptoKey (https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)
```

### Example

```js
const attestation = await navigator.credentials.create({
  // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
  publicKey: {
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
    challenge,
    pubKeyCredParams: [{alg: -7, type: 'public-key'}],
    rp: {name: 'Acme, inc.'},
    user: {
      id: new Uint8Array([
        169, 65, 116, 220, 58, 131, 135, 194, 166, 236, 37, 43, 65, 67, 138, 235,
      ]),
      name: 'john_doe',
      displayName: 'john_doe',
    },
  },
})
const key = importKey({
  algorithm: attestation.response.getPublicKeyAlgorithm(),
  data: attestation.response.getPublicKey(),
})
```

## `verifySignature()`

Verify the signature of a Passkey assertion ("log in").

```js
verifySignature({
  key, // CryptoKey (e.g. return value of `ImportKey`)
  authenticatorData, // ArrayBuffer, TypedArray, or DataView
  clientDataJSON, // ArrayBuffer, TypedArray, or DataView
  signature, // ArrayBuffer, TypedArray, or DataView
}) // → true/false
```

### Example

```js
const assertion = await navigator.credentials.get({
  // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
  publicKey: {
    challenge: new Uint8Array([
      81, 171, 233, 210, 73, 148, 27, 141, 244, 227, 163, 237, 182, 58, 191, 57,
    ]),
  },
})
const key = importKey(/**/)
const verified = verifySignature({
  key,
  authenticatorData: assertion.response.authenticatorData,
  clientDataJSON: assertion.response.clientDataJSON,
  signature: assertion.response.signature,
})
```

## `getChallenge()`

Extract the challenge from a `clientDataJSON` value.

If `clientDataJSON` is not guaranteed to be valid, e.g. originates from a user,
the operation should be wrapped in a try-catch block.

```js
getChallenge(clientDataJSON) // → Uint8Array
```

### Example

```js
const serverChallenge = new Uint8Array([
  81, 171, 233, 210, 73, 148, 27, 141, 244, 227, 163, 237, 182, 58, 191, 57,
])
const assertion = await navigator.credentials.get({
  // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
  publicKey: {
    challenge: serverChallenge,
  },
})
const signedChallenge = getChallenge(assertion.response.clientDataJSON)
if (!equals(serverChallenge, signedChallenge)) {
  throw new Error('Invalid challenge')
}
```

## `parseClientDataJSON()`

Parse the `clientDataJSON` of a Passkey attestation or assertion response.

If `clientDataJSON` is not guaranteed to be valid, e.g. originates from a user,
the operation should be wrapped in a try-catch block.

```js
parseClientDataJSON(
  clientDataJSON, // ArrayBuffer, TypedArray, or DataView
) // → JSON
```

### Example

```js
const attestation = await navigator.credentials.create({
  // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
  publicKey: {
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
    challenge,
    pubKeyCredParams: [{alg: -7, type: 'public-key'}],
    rp: {name: 'Acme, inc.'},
    user: {
      id: new Uint8Array([
        169, 65, 116, 220, 58, 131, 135, 194, 166, 236, 37, 43, 65, 67, 138, 235,
      ]),
      name: 'john_doe',
      displayName: 'john_doe',
    },
  },
})
parseClientDataJSON(attestation.response.clientDataJSON)
// → {
//   type: 'webauthn.create',
//   challenge: 'gDbf5ICIv3bIM_cpGaHvlw',
//   origin: 'http://localhost:4507',
//   crossOrigin: false,
// }
```

## `parseAuthenticatorData()`

Parse the `getAuthenticatorData()` return value of a Passkey attestation or
assertion response.

The operation will throw an exception if the input is less than 33 bytes.

```js
parseAuthenticatorData(
  authenticatorData, // ArrayBuffer, TypedArray, or DataView
)
// → {
//  userPresence: Boolean,
//  userVerification: Boolean,
//  backupEligibility: Boolean,
//  backupState: Boolean,
// }
```

### Example

```js
const attestation = await navigator.credentials.create({
  // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
  publicKey: {
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
    challenge,
    pubKeyCredParams: [{alg: -7, type: 'public-key'}],
    rp: {name: 'Acme, inc.'},
    user: {
      id: new Uint8Array([
        169, 65, 116, 220, 58, 131, 135, 194, 166, 236, 37, 43, 65, 67, 138, 235,
      ]),
      name: 'john_doe',
      displayName: 'john_doe',
    },
  },
})
parseAuthenticatorData(attestation.response.getAuthenticatorData())
// → {
//  userPresence: true,
//  userVerification: true,
//  backupEligibility: false,
//  backupState: false,
// }
```

## Testing

```sh
deno --allow-env --allow-read test.js
```
