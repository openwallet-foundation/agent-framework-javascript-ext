import type {
  AutoAcceptCredential,
  CredentialFormatPayload,
  IndyCredentialFormat,
  ProofRecord,
  ProtocolVersionType,
  V1CredentialService,
  V2CredentialService,
} from '@aries-framework/core'

export interface AgentInfo {
  label: string
  endpoints: string[]
  isInitialized: boolean
  publicDid?: {
    did: string
    verkey: string
  }
}

/**
 * @example "821f9b26-ad04-4f56-89b6-e2ef9c72b36e"
 */
export type RecordId = string

/**
 * @example "WgWxqztrNooG92RXvxSTWv:3:CL:20:tag"
 */
export type CredentialDefinitionId = string

/**
 * @example "WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0"
 */
export type SchemaId = string

export interface ProofRequestMessageResponse {
  message: string
  proofRecord: ProofRecord
}

type CredentialFormats = [IndyCredentialFormat]
type CredentialServices = [V1CredentialService, V2CredentialService]

export interface ProposeCredentialOptions {
  protocolVersion: ProtocolVersionType<CredentialServices>
  credentialFormats: CredentialFormatPayload<CredentialFormats, 'createProposal'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
  connectionId: string
}

export interface AcceptCredentialProposalOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormats, 'acceptProposal'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

export interface OfferCredentialOptions {
  protocolVersion: ProtocolVersionType<CredentialServices>
  credentialFormats: CredentialFormatPayload<CredentialFormats, 'createOffer'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
  connectionId: string
}

export interface AcceptCredentialOfferOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormats, 'acceptOffer'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

export interface AcceptCredentialRequestOptions {
  credentialRecordId: string
  credentialFormats?: CredentialFormatPayload<CredentialFormats, 'acceptRequest'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}
