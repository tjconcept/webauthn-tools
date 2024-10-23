import test from 'https://esm.sh/tape@5.9.0'
import {decodeBase64Url} from 'https://esm.sh/jsr/@std/encoding@1.0.5/base64url.js'
import join from 'https://esm.sh/psjoin@1.0.0'
import {
	importKey,
	getChallenge,
	parseClientDataJSON,
	parseAuthenticatorData,
	verifySignature,
} from './index.js'

test('`importKey`', async (t) => {
	t.test('supported algorithms', async (t) => {
		const keys = [
			[-8, 'MCowBQYDK2VwAyEAL7milh-tbyuXCwCBtgIxCgZA6HMdV8d6YaBSC_LFxN4'],
			[
				-257,
				'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsxGh7GzeTrMgadrjdvlghyoMUtKXyKkBb23xFul5FCOxKkY4uSKA-TLO7Yh8Fd3RgsJHjDr2TH2kqH1IxbCZds2e9xz2GSUz0EK8SAALVJtjf1M3eicIaFSXSf88lIGms1Zm_cMSrp3PM0SQSwFAXylF3SXgD-Sz7ISqhyMSpmUNEI1Y9NieJDsEHL0efyyzpeis8L1PHYHcCj0sUOntOi3VKVY_AYKMsM0vpXlwYfQbqcQA_nV3MrpjgzIWjarGsODWa2hP5GPovZwbVg2WbARjqoyaP_cQ3StofWMAqIsM7cLny4BIKhNiHqNDGK2qOOiSGs4azU3ISZz7-JoN3wIDAQAB',
			],
			[
				-7,
				'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAD9X-HUEQqLo6ld7CgpRwRIJkXMWuWfLyVn16N7syL4C_5WPRkE5kXhcU-yy-FGSBJNGUhlPqJueJxGJBtcU7g',
			],
		]
		for (const [algorithm, data] of keys) {
			await importKey({
				algorithm,
				data: decodeBase64Url(data),
			}).then(() => t.pass(`algorithm: ${algorithm}`))
		}
	})
	t.test('data types', async (t) => {
		const data = decodeBase64Url(
			'MCowBQYDK2VwAyEAL7milh-tbyuXCwCBtgIxCgZA6HMdV8d6YaBSC_LFxN4',
		)
		await importKey({
			algorithm: -8,
			data: data.buffer,
		}).then(() => t.pass('as an ArrayBuffer'))
		await importKey({
			algorithm: -8,
			data: new DataView(data.buffer),
		}).then(() => t.pass('as a DataView'))
		await importKey({
			algorithm: -8,
			data: {
				kty: 'OKP',
				crv: 'Ed25519',
				x: 'L7milh-tbyuXCwCBtgIxCgZA6HMdV8d6YaBSC_LFxN4',
				key_ops: ['verify'],
				ext: true,
			},
		}).then(() => t.pass('as a JSON Web Key'))
	})
	t.test('extractable', async (t) => {
		const data = decodeBase64Url(
			'MCowBQYDK2VwAyEAL7milh-tbyuXCwCBtgIxCgZA6HMdV8d6YaBSC_LFxN4',
		)
		t.test('default', async (t) => {
			const key = await importKey({
				algorithm: -8,
				data,
			})
			t.equal(key.extractable, false, 'is `false`')
		})
		t.test('explicit `false`', async (t) => {
			const key = await importKey({
				algorithm: -8,
				data,
				extractable: false,
			})
			t.equal(key.extractable, false)
		})
		t.test('explicit `true`', async (t) => {
			const key = await importKey({
				algorithm: -8,
				data,
				extractable: true,
			})
			t.equal(key.extractable, true)
		})
	})
})

test('`verifySignature`', async (t) => {
	const fixtures = [
		[
			-8,
			'MCowBQYDK2VwAyEAL7milh-tbyuXCwCBtgIxCgZA6HMdV8d6YaBSC_LFxN4',
			{
				authenticatorData:
					'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg',
				clientDataJSON:
					'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHRuMDh5YUowZnJxZXgtd05jQ0lLdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
				signature:
					'dyfN_CoMPijGVyiBy5Udfe6Bc09hvRedjpBdVMr3D2-PVPkt_lmVwHBp6qpMDI_mJcei6niJxyqbMQvQZzwvAg',
				userHandle: 'sKVD_BnoSpi7GUaxok9EFA',
			},
		],
		[
			-257,
			'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsxGh7GzeTrMgadrjdvlghyoMUtKXyKkBb23xFul5FCOxKkY4uSKA-TLO7Yh8Fd3RgsJHjDr2TH2kqH1IxbCZds2e9xz2GSUz0EK8SAALVJtjf1M3eicIaFSXSf88lIGms1Zm_cMSrp3PM0SQSwFAXylF3SXgD-Sz7ISqhyMSpmUNEI1Y9NieJDsEHL0efyyzpeis8L1PHYHcCj0sUOntOi3VKVY_AYKMsM0vpXlwYfQbqcQA_nV3MrpjgzIWjarGsODWa2hP5GPovZwbVg2WbARjqoyaP_cQ3StofWMAqIsM7cLny4BIKhNiHqNDGK2qOOiSGs4azU3ISZz7-JoN3wIDAQAB',
			{
				authenticatorData:
					'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg',
				clientDataJSON:
					'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNmRYaTA1R25qMVd5eHdRQ2FpY3FjdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
				signature:
					'QfGF0wqRew83d9gwfWUVV_pGjqbItBD77GVdVzAQkSfT5VklQqt1cYTrOWMjrRFsIilBQ_Yolm4-FjSknTvcb8Su7slB7nVbcasB2LDzg8mVLtRUYJobCL-aEWAp7cq2jxxVgLdIUZHIH-J4F9hwfmdCA7eOO25NxzvsudK-P9uA-QeXeze4mHq2n5Y8bC2OM7JXc9JEAFiQ-sExgdm8tLnZIjykkgBbrOr2eOfVEEI2Nv5C1jaWTJ587Z_enUjFp9TolCJgwcmSwdmV8eku_dQ6hEjE09VPLwoNBp_IIwtevDn9k-22bhMViPOs2mlZ8nWHoMIDeP7BXb-rSuVXRw',
				userHandle: 'S_qBcX8W-yqWBcD1BlmO3A',
			},
		],
		[
			-7,
			'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAD9X-HUEQqLo6ld7CgpRwRIJkXMWuWfLyVn16N7syL4C_5WPRkE5kXhcU-yy-FGSBJNGUhlPqJueJxGJBtcU7g',
			{
				authenticatorData:
					'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAw',
				clientDataJSON:
					'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaHRYWnJ1UVFzSzhjQ0FyLTBJUFBMQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
				signature:
					'MEQCIEtcxcn8BRm6BmZE3vghukbX-PcMR8o9WWBJI03RC4B0AiAYnBdiX1RMdUelPaAfqlwF92HqpDEgwfUErp4VoDCqZg',
				userHandle: 'Emoes5m8250vw7ItnM7-nw',
			},
		],
	]
	t.test('supported algorithms', async (t) => {
		for (const [algorithm, keyData, assertionResponse] of fixtures) {
			const key = await importKey({
				algorithm,
				data: decodeBase64Url(keyData),
			})
			t.equal(
				await verifySignature({
					key,
					authenticatorData: decodeBase64Url(
						assertionResponse.authenticatorData,
					),
					clientDataJSON: decodeBase64Url(
						assertionResponse.clientDataJSON,
					),
					signature: decodeBase64Url(assertionResponse.signature),
				}),
				true,
				`algorithm: ${algorithm}`,
			)
		}
	})
	t.test('mismatching key-signature', async (t) => {
		const [algorithm, keyData] = fixtures[0]
		const [, , assertionResponse] = fixtures[1]
		const key = await importKey({
			algorithm,
			data: decodeBase64Url(keyData),
		})
		t.equal(
			await verifySignature({
				key,
				authenticatorData: decodeBase64Url(
					assertionResponse.authenticatorData,
				),
				clientDataJSON: decodeBase64Url(
					assertionResponse.clientDataJSON,
				),
				signature: decodeBase64Url(assertionResponse.signature),
			}),
			false,
		)
	})
	t.test('mismatching authenticatorData-signature', async (t) => {
		const [algorithm, keyData, assertionResponse] = fixtures[0]
		const key = await importKey({
			algorithm,
			data: decodeBase64Url(keyData),
		})
		t.equal(
			await verifySignature({
				key,
				authenticatorData: new Uint8Array(32),
				clientDataJSON: decodeBase64Url(
					assertionResponse.clientDataJSON,
				),
				signature: decodeBase64Url(assertionResponse.signature),
			}),
			false,
		)
	})
	t.test('mismatching clientDataJSON-signature', async (t) => {
		const [algorithm, keyData, assertionResponse] = fixtures[0]
		const key = await importKey({
			algorithm,
			data: decodeBase64Url(keyData),
		})
		t.equal(
			await verifySignature({
				key,
				authenticatorData: decodeBase64Url(
					assertionResponse.authenticatorData,
				),
				clientDataJSON: new Uint8Array(32),
				signature: decodeBase64Url(assertionResponse.signature),
			}),
			false,
		)
	})
	t.test('invalid signature', async (t) => {
		const [algorithm, keyData, assertionResponse] = fixtures[0]
		const key = await importKey({
			algorithm,
			data: decodeBase64Url(keyData),
		})
		t.equal(
			await verifySignature({
				key,
				authenticatorData: decodeBase64Url(
					assertionResponse.authenticatorData,
				),
				clientDataJSON: decodeBase64Url(
					assertionResponse.clientDataJSON,
				),
				signature: new Uint8Array(32),
			}),
			false,
		)
	})
})

test('`getChallenge`', async (t) => {
	t.deepEqual(
		getChallenge(
			decodeBase64Url(
				'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ0RiZjVJQ0l2M2JJTV9jcEdhSHZsdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
			),
		),
		new Uint8Array([
			128, 54, 223, 228, 128, 136, 191, 118, 200, 51, 247, 41, 25, 161,
			239, 151,
		]),
		'from an attestation',
	)
	t.deepEqual(
		getChallenge(
			decodeBase64Url(
				'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHRuMDh5YUowZnJxZXgtd05jQ0lLdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
			),
		),
		new Uint8Array([
			182, 217, 244, 243, 38, 137, 209, 250, 234, 123, 31, 176, 53, 192,
			136, 43,
		]),
		'from an assertion',
	)
	t.throws(
		() =>
			getChallenge(
				decodeBase64Url(
					'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHRuMDh5YUowZnJxZXgtd05jQ0lLdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6DNUwNIysmIybN3Nz3TJZp2lujImpYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb12YwXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
				),
			),
		{
			name: 'SyntaxError',
			message:
				'Bad control character in string literal in JSON at position 87 (line 1 column 88)',
		},
		'Invalid string',
	)
	t.throws(
		() => getChallenge(new TextEncoder().encode('{"invalid":JSON}')),
		{
			name: 'SyntaxError',
			message:
				'Unexpected token \'J\', "{"invalid":JSON}" is not valid JSON',
		},
		'Invalid JSON string',
	)
})

test('`parseClientDataJSON`', async (t) => {
	t.deepEqual(
		parseClientDataJSON(
			decodeBase64Url(
				'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ0RiZjVJQ0l2M2JJTV9jcEdhSHZsdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
			),
		),
		{
			type: 'webauthn.create',
			challenge: 'gDbf5ICIv3bIM_cpGaHvlw',
			origin: 'http://localhost:4507',
			crossOrigin: false,
		},
		'from an attestation',
	)
	t.deepEqual(
		parseClientDataJSON(
			decodeBase64Url(
				'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHRuMDh5YUowZnJxZXgtd05jQ0lLdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDUwNyIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
			),
		),
		{
			type: 'webauthn.get',
			challenge: 'ttn08yaJ0frqex-wNcCIKw',
			origin: 'http://localhost:4507',
			crossOrigin: false,
			other_keys_can_be_added_here:
				'do not compare clientDataJSON against a template. See https://goo.gl/yabPex',
		},
		'from an assertion',
	)
	t.throws(
		() =>
			parseClientDataJSON(
				decodeBase64Url(
					'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHRuMDh5YUowZnJxZXgtd05jQ0lLdyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6DNUwNIysmIybN3Nz3TJZp2lujImpYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb12YwXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9',
				),
			),
		{
			name: 'SyntaxError',
			message:
				'Bad control character in string literal in JSON at position 87 (line 1 column 88)',
		},
		'Invalid string',
	)
	t.throws(
		() => parseClientDataJSON(new TextEncoder().encode('{"invalid":JSON}')),
		{
			name: 'SyntaxError',
			message:
				'Unexpected token \'J\', "{"invalid":JSON}" is not valid JSON',
		},
		'Invalid JSON string',
	)
})

test('`parseAuthenticatorData`', (t) => {
	const attestation = decodeBase64Url(
		'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIKlBdNw6g4fCpuwlK0FDius666Zu_RCDkd9QzA7RFvcRpAEBAycgBiFYIC-5opYfrW8rlwsAgbYCMQoGQOhzHVfHemGgUgvyxcTe',
	)
	const assertion = decodeBase64Url(
		'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg',
	)
	t.deepEqual(
		parseAuthenticatorData(attestation),
		{
			userPresence: true,
			userVerification: true,
			backupEligibility: false,
			backupState: false,
		},
		'from an attestation',
	)
	t.deepEqual(
		parseAuthenticatorData(assertion),
		{
			userPresence: true,
			userVerification: true,
			backupEligibility: false,
			backupState: false,
		},
		'from an assertion',
	)
	t.throws(() => parseAuthenticatorData(new Uint8Array(32)), {
		name: 'RangeError',
		message: 'Offset is outside the bounds of the DataView',
	})
	t.end()
})
