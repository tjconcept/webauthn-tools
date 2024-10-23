import {decodeBase64Url} from 'https://esm.sh/jsr/@std/encoding@1.0.5/base64url.js'
import {concat} from 'https://esm.sh/jsr/@std/bytes@1.0.2/concat.js'
import join from 'https://esm.sh/psjoin@1.0.0'

const importOptionsByCose = new Map([
	[-8, {name: 'Ed25519'}],
	[-7, {name: 'ECDSA', namedCurve: 'P-256'}],
	[-257, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'}],
])
const verifyOptionsByKey = new Map([
	['Ed25519', {name: 'Ed25519'}],
	['ECDSA', {name: 'ECDSA', hash: 'SHA-256'}],
	['RSASSA-PKCS1-v1_5', {name: 'RSASSA-PKCS1-v1_5'}],
])

export function importKey({algorithm, data, extractable = false}) {
	const format = data.kty !== undefined ? 'jwk' : 'spki'
	return crypto.subtle.importKey(
		format,
		data,
		importOptionsFromCose(algorithm),
		extractable,
		['verify'],
	)
}

export function getChallenge(clientDataJSON) {
	const parsed = parseClientDataJSON(clientDataJSON)
	return decodeBase64Url(parsed.challenge)
}

export function parseClientDataJSON(data) {
	return JSON.parse(new TextDecoder().decode(data))
}

export function parseAuthenticatorData(authenticatorData) {
	// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data#flags
	const view = new DataView(
		ArrayBuffer.isView(authenticatorData)
			? authenticatorData.buffer
			: authenticatorData,
	)
	const flags = view.getUint8(32)
	// prettier-ignore
	return {
		userPresence:      (flags & 0b00000001) !== 0,
		userVerification:  (flags & 0b00000100) !== 0,
		backupEligibility: (flags & 0b00001000) !== 0,
		backupState:       (flags & 0b00010000) !== 0,
	}
}

export function verifySignature({
	key,
	authenticatorData,
	clientDataJSON,
	signature,
}) {
	const clientDataHash = crypto.subtle.digest('SHA-256', clientDataJSON)
	const normalizedSignature =
		key.algorithm.name === 'ECDSA'
			? unwrapAsn1Signature(signature)
			: signature
	const signed = join(clientDataHash, (clientDataHash) =>
		concat([authenticatorData, new Uint8Array(clientDataHash)]),
	)
	return join(signed, (signed) =>
		crypto.subtle.verify(
			verifyOptionsFromKey(key),
			key,
			normalizedSignature,
			signed,
		),
	)
}

// Credit: https://www.criipto.com/blog/webauthn-ecdsa-signature
// Alternatively use an ASN.1 library
// See also https://gist.github.com/philholden/50120652bfe0498958fd5926694ba354
function unwrapAsn1Signature(input) {
	const elements = readAsn1IntegerSequence(input)
	if (elements.length !== 2) {
		throw new Error('Expected 2 ASN.1 sequence elements')
	}

	let [r, s] = elements

	// R and S length is assumed multiple of 128bit.
	// If leading is 0 and modulo of length is 1 byte then
	// leading 0 is for two's complement and will be removed.
	if (r[0] === 0 && r.byteLength % 16 == 1) {
		r = r.slice(1)
	}
	if (s[0] === 0 && s.byteLength % 16 == 1) {
		s = s.slice(1)
	}

	// R and S length is assumed multiple of 128bit.
	// If missing a byte then it will be padded by 0.
	if (r.byteLength % 16 == 15) {
		r = concat([new Uint8Array([0]), r])
	}
	if (s.byteLength % 16 == 15) {
		s = concat([new Uint8Array([0]), s])
	}

	// If R and S length is not still multiple of 128bit,
	// then error
	if (r.byteLength % 16 != 0) {
		throw Error('Unknown ECDSA sig r length error')
	}

	if (s.byteLength % 16 != 0) {
		throw Error('Unknown ECDSA sig s length error')
	}

	return concat([r, s])
}

function readAsn1IntegerSequence(input) {
	if (input[0] !== 0x30) {
		throw new Error('Input is not an ASN.1 sequence')
	}

	const seqLength = input[1]
	const elements = []
	let current = input.slice(2, 2 + seqLength)
	while (current.length > 0) {
		const tag = current[0]
		if (tag !== 0x02) {
			throw new Error('Expected ASN.1 sequence element to be an INTEGER')
		}

		const elLength = current[1]
		elements.push(current.slice(2, 2 + elLength))
		current = current.slice(2 + elLength)
	}
	return elements
}

function importOptionsFromCose(algorithm) {
	const found = importOptionsByCose.get(algorithm)
	if (found === undefined) {
		throw new Error(`Unknown key algorithm (COSE). Got ${algorithm}.`)
	}

	return found
}

function verifyOptionsFromKey(key) {
	const found = verifyOptionsByKey.get(key.algorithm.name)
	if (found === undefined) {
		throw new Error(`Unknown key algorithm. Got "${key.algorithm.name}".`)
	}

	return found
}
