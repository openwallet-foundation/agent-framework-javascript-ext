/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { WebhookData } from './utils/webhook'
import type { Agent, CredentialStateChangedEvent, ProofStateChangedEvent } from '@aries-framework/core'
import type { Server } from 'http'

import {
  CredentialExchangeRecord,
  ProofEventTypes,
  ProofState,
  ProofRecord,
  CredentialState,
  CredentialEventTypes,
} from '@aries-framework/core'
import { EventEmitter } from '@aries-framework/core/build/agent/EventEmitter'

import { setupServer } from '../src/server'

import { getTestAgent } from './utils/helpers'
import { sleep, webhookListener } from './utils/webhook'

describe('WebhookTest', () => {
  let aliceAgent: Agent
  let bobAgent: Agent
  let server: Server
  const webhooks: WebhookData[] = []

  beforeAll(async () => {
    aliceAgent = await getTestAgent('Rest Webhook Test Alice', 3042)
    bobAgent = await getTestAgent('Rest Webhook Test Bob', 3043)
    server = await webhookListener(3044, webhooks)
    await setupServer(bobAgent, { webhookUrl: 'http://localhost:3044', port: 3000 })
  })

  test('should return a webhook event when basic message state changed', async () => {
    const { outOfBandInvitation } = await aliceAgent.oob.createInvitation()
    const { connectionRecord } = await bobAgent.oob.receiveInvitation(outOfBandInvitation)
    const connection = await bobAgent.connections.returnWhenIsConnected(connectionRecord!.id)

    await bobAgent.basicMessages.sendMessage(connection.id, 'Hello')

    /*
     * A sleep is placed here to wait for the event to have processed and sent out
     * an webhook first before searching for the webhook
     */
    await sleep(100)

    const webhook = webhooks.find((webhook) => webhook.topic !== 'connections')

    expect(webhook).toBeDefined()
  })

  test('should return a webhook event when connection state changed', async () => {
    const { outOfBandInvitation } = await aliceAgent.oob.createInvitation()
    const { connectionRecord } = await bobAgent.oob.receiveInvitation(outOfBandInvitation)
    const connection = await bobAgent.connections.returnWhenIsConnected(connectionRecord!.id)

    /*
     * A sleep is placed here to wait for the event to have processed and sent out
     * an webhook first before searching for the webhook
     */
    await sleep(100)

    const webhook = webhooks.find(
      (webhook) =>
        webhook.topic === 'connections' && webhook.body.id === connection.id && webhook.body.state === connection.state
    )

    expect(JSON.parse(JSON.stringify(connection.toJSON()))).toMatchObject(webhook?.body as Record<string, unknown>)
  })

  test('should return a webhook event when credential state changed', async () => {
    const credentialRecord = new CredentialExchangeRecord({
      id: 'testest',
      state: CredentialState.OfferSent,
      threadId: 'random',
      protocolVersion: 'v1',
    })

    const eventEmitter = bobAgent.injectionContainer.resolve(EventEmitter)
    eventEmitter.emit<CredentialStateChangedEvent>({
      type: CredentialEventTypes.CredentialStateChanged,
      payload: {
        previousState: null,
        credentialRecord,
      },
    })

    /*
     * A sleep is placed here to wait for the event to have processed and sent out
     * an webhook first before searching for the webhook
     */
    await sleep(100)

    const webhook = webhooks.find(
      (webhook) =>
        webhook.topic === 'credentials' &&
        webhook.body.id === credentialRecord.id &&
        webhook.body.state === credentialRecord.state
    )

    expect(JSON.parse(JSON.stringify(credentialRecord.toJSON()))).toMatchObject(
      webhook?.body as Record<string, unknown>
    )
  })

  test('should return a webhook event when proof state changed', async () => {
    const proofRecord = new ProofRecord({
      id: 'testest',
      state: ProofState.ProposalSent,
      threadId: 'random',
    })

    const eventEmitter = bobAgent.injectionContainer.resolve(EventEmitter)
    eventEmitter.emit<ProofStateChangedEvent>({
      type: ProofEventTypes.ProofStateChanged,
      payload: {
        previousState: null,
        proofRecord,
      },
    })

    /*
     * A sleep is placed here to wait for the event to have processed and sent out
     * an webhook first before searching for the webhook
     */
    await sleep(100)

    const webhook = webhooks.find(
      (webhook) =>
        webhook.topic === 'proofs' && webhook.body.id === proofRecord.id && webhook.body.state === proofRecord.state
    )

    expect(JSON.parse(JSON.stringify(proofRecord.toJSON()))).toMatchObject(webhook?.body as Record<string, unknown>)
  })

  afterAll(async () => {
    await aliceAgent.shutdown()
    await aliceAgent.wallet.delete()
    await bobAgent.shutdown()
    await bobAgent.wallet.delete()
    server.close()
  })
})
