import type { RestRootAgent } from '../../../../utils/agent'
import type { KeyDidCreateOptions, SdJwtVcRecord } from '@credo-ts/core'
import type { OpenId4VcVerificationSessionStateChangedEvent } from '@credo-ts/openid4vc'

import { DidKey, KeyType } from '@credo-ts/core'
import { OpenId4VcVerificationSessionState, OpenId4VcVerifierEvents } from '@credo-ts/openid4vc'
import express from 'express'
import { filter, first, firstValueFrom, timeout } from 'rxjs'
import request from 'supertest'

import { getTestAgent } from '../../../../../tests/utils/helpers'
import { setupApp } from '../../../../setup/setupApp'

describe('OpenId4VcVerificationSessionsController', () => {
  const app = express()
  let agent: RestRootAgent
  let issuerDidKey: DidKey
  let holderDidKey: DidKey
  let holderSdJwtVcRecord: SdJwtVcRecord

  beforeAll(async () => {
    agent = await getTestAgent('OpenID4VC Verifications Sessions REST Agent Test', 4848)
    await setupApp({ agent, adminPort: 3000, baseApp: app })

    await agent.modules.openId4VcVerifier.createVerifier({
      verifierId: 'publicVerifierId',
    })
    const issuerDidResult = await agent.dids.create<KeyDidCreateOptions>({
      method: 'key',
      options: {
        keyType: KeyType.Ed25519,
      },
    })
    const holderDidResult = await agent.dids.create<KeyDidCreateOptions>({
      method: 'key',
      options: {
        keyType: KeyType.Ed25519,
      },
    })
    issuerDidKey = DidKey.fromDid(issuerDidResult.didState.did as string)
    holderDidKey = DidKey.fromDid(holderDidResult.didState.did as string)
    const sdJwtVc = await agent.sdJwtVc.sign({
      holder: {
        didUrl: `${holderDidKey.did}#${holderDidKey.key.fingerprint}`,
        method: 'did',
      },
      issuer: {
        didUrl: `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`,
        method: 'did',
      },
      payload: {
        vct: 'https://example.com/vct',
        first_name: 'John',
        age: {
          over_21: true,
          over_18: true,
          over_65: false,
        },
      },
      disclosureFrame: {
        first_name: false,
        age: {
          over_18: true,
          over_21: true,
          over_65: true,
        },
      },
    })
    holderSdJwtVcRecord = await agent.sdJwtVc.store(sdJwtVc.compact)
  })

  afterAll(async () => {
    await agent.shutdown()
    await agent.wallet.delete()
  })

  test('create request', async () => {
    const response = await request(app)
      .post(`/openid4vc/verifiers/sessions/create-request`)
      .send({
        publicVerifierId: 'publicVerifierId',
        requestSigner: {
          method: 'did',
          didUrl: `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`,
        },
        presentationExchange: {
          definition: {
            id: '73797b0c-dae6-46a7-9700-7850855fee22',
            name: 'Example Presentation Definition',
            input_descriptors: [
              {
                id: '64125742-8b6c-422e-82cd-1beb5123ee8f',
                constraints: {
                  limit_disclosure: 'required',
                  fields: [
                    {
                      path: ['$.age.over_18'],
                      filter: {
                        type: 'boolean',
                      },
                    },
                  ],
                },
                name: 'Requested Sd Jwt Example Credential',
                purpose: 'To provide an example of requesting a credential',
              },
            ],
          },
        },
      })

    expect(response.statusCode).toBe(200)
    expect(response.body).toEqual({
      verificationSession: {
        createdAt: expect.any(String),
        id: expect.any(String),
        publicVerifierId: expect.any(String),
        state: 'RequestCreated',
        type: 'OpenId4VcVerificationSessionRecord',
        updatedAt: expect.any(String),
        authorizationRequestJwt: expect.stringContaining('ey'),
        authorizationRequestUri: expect.stringContaining(
          'http://localhost:4848/siop/publicVerifierId/authorization-requests/',
        ),
      },
      authorizationRequest: expect.stringContaining(
        `openid4vp://?request_uri=${encodeURIComponent(`http://localhost:4848/siop/publicVerifierId/authorization-requests/`)}`,
      ),
    })

    const presentationVerified = firstValueFrom(
      agent.events
        .observable<OpenId4VcVerificationSessionStateChangedEvent>(
          OpenId4VcVerifierEvents.VerificationSessionStateChanged,
        )
        .pipe(
          filter(
            (event) =>
              event.payload.verificationSession.state === OpenId4VcVerificationSessionState.ResponseVerified &&
              event.payload.verificationSession.id === response.body.verificationSession.id,
          ),
          first(),
          timeout(10000),
        ),
    )

    const resolvedAuthorizationRequest = await agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
      response.body.authorizationRequest,
    )
    const { serverResponse } = await agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
      authorizationRequest: resolvedAuthorizationRequest.authorizationRequest,
      presentationExchange: {
        credentials: {
          '64125742-8b6c-422e-82cd-1beb5123ee8f': [holderSdJwtVcRecord],
        },
      },
    })

    const presentationVerifiedEvent = await presentationVerified
    expect(serverResponse.status).toEqual(200)

    const verifiedResponse = await request(app).get(
      `/openid4vc/verifiers/sessions/${presentationVerifiedEvent.payload.verificationSession.id}/verified-authorization-response`,
    )

    expect(verifiedResponse.body).toEqual({
      idToken: {
        payload: {
          aud: issuerDidKey.did,
          exp: expect.any(Number),
          iat: expect.any(Number),
          iss: holderDidKey.did,
          nonce: expect.any(String),
          state: expect.any(String),
          sub: holderDidKey.did,
        },
      },
      presentationExchange: {
        definition: {
          id: '73797b0c-dae6-46a7-9700-7850855fee22',
          input_descriptors: [
            {
              constraints: {
                fields: [
                  {
                    filter: {
                      type: 'boolean',
                    },
                    path: ['$.age.over_18'],
                  },
                ],
                limit_disclosure: 'required',
              },
              id: '64125742-8b6c-422e-82cd-1beb5123ee8f',
              name: 'Requested Sd Jwt Example Credential',
              purpose: 'To provide an example of requesting a credential',
            },
          ],
          name: 'Example Presentation Definition',
        },
        presentations: [
          {
            encoded: expect.any(String),
            format: 'vc+sd-jwt',
            header: {
              alg: 'EdDSA',
              kid: `#${issuerDidKey.key.fingerprint}`,
              typ: 'vc+sd-jwt',
            },
            signedPayload: {
              _sd_alg: 'sha-256',
              age: {
                _sd: [expect.any(String), expect.any(String), expect.any(String)],
              },
              cnf: {
                kid: `${holderDidKey.did}#${holderDidKey.key.fingerprint}`,
              },
              first_name: 'John',
              iat: expect.any(Number),
              iss: issuerDidKey.did,
              vct: 'https://example.com/vct',
            },
            vcPayload: {
              age: {
                over_18: true,
              },
              cnf: {
                kid: `${holderDidKey.did}#${holderDidKey.key.fingerprint}`,
              },
              first_name: 'John',
              iat: expect.any(Number),
              iss: issuerDidKey.did,
              vct: 'https://example.com/vct',
            },
          },
        ],
        submission: {
          definition_id: '73797b0c-dae6-46a7-9700-7850855fee22',
          descriptor_map: [
            {
              format: 'vc+sd-jwt',
              id: '64125742-8b6c-422e-82cd-1beb5123ee8f',
              path: '$',
            },
          ],
          id: expect.any(String),
        },
      },
    })
  })
})
