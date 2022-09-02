import type {
  Attachment,
  AutoAcceptCredential,
  AutoAcceptProof,
  CredentialFormatPayload,
  HandshakeProtocol,
  IndyCredentialFormat,
  PresentationPreviewAttributeOptions,
  PresentationPreviewPredicateOptions,
  ProofAttributeInfo,
  ProofPredicateInfo,
  ProofRecord,
  ProofRequestConfig,
  ProtocolVersionType,
  ReceiveOutOfBandInvitationConfig,
  Routing,
  V1CredentialService,
  V2CredentialService,
  OutOfBandDidCommService,
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

export interface ProofRequestMessageResponse {
  message: string
  proofRecord: ProofRecord
}

type CredentialFormats = [IndyCredentialFormat]
type CredentialServices = [V1CredentialService, V2CredentialService]

export interface ProposeCredentialOptions {
  protocolVersion: ProtocolVersionType<CredentialServices>
  credentialFormats: {
    indy: {
      schemaIssuerDid: string
      schemaId: string
      schemaName: string
      schemaVersion: string
      credentialDefinitionId: string
      issuerDid: string
      attributes: {
        name: string
        mimeType: string
        value: string
      }[]
    }
  }
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
  connectionId: string
}

export interface AcceptCredentialProposalOptions {
  credentialFormats?: {
    indy: {
      credentialDefinitionId: string
      attributes: {
        name: string
        mimeType: string
        value: string
      }[]
    }
  }
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

export interface OfferCredentialOptions {
  protocolVersion: ProtocolVersionType<CredentialServices>
  credentialFormats: {
    indy: {
      credentialDefinitionId: string
      attributes: {
        name: string
        mimeType: string
        value: string
      }[]
    }
  }
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
  connectionId: string
}

export interface AcceptCredentialOfferOptions {
  credentialFormats?: CredentialFormatPayload<CredentialFormats, 'acceptOffer'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

export interface AcceptCredentialRequestOptions {
  credentialFormats?: CredentialFormatPayload<CredentialFormats, 'acceptRequest'>
  autoAcceptCredential?: AutoAcceptCredential
  comment?: string
}

type ReceiveOutOfBandInvitationProps = Omit<ReceiveOutOfBandInvitationConfig, 'routing'>

export interface ReceiveInvitationProps extends ReceiveOutOfBandInvitationProps {
  invitation: Omit<OutOfBandInvitationSchema, 'appendedAttachments'>
}

export interface ReceiveInvitationByUrlProps extends ReceiveOutOfBandInvitationProps {
  invitationUrl: string
}

export interface AcceptInvitationConfig {
  autoAcceptConnection?: boolean
  reuseConnection?: boolean
  label?: string
  alias?: string
  imageUrl?: string
  mediatorId?: string
}

export interface OutOfBandInvitationSchema {
  '@id'?: string
  '@type': string
  label: string
  goalCode?: string
  goal?: string
  accept?: string[]
  handshake_protocols?: HandshakeProtocol[]
  services: Array<OutOfBandDidCommService | string>
  imageUrl?: string
}

export interface ConnectionInvitationSchema {
  id?: string
  '@type': string
  label: string
  did?: string
  recipientKeys?: string[]
  serviceEndpoint?: string
  routingKeys?: string[]
  imageUrl?: string
}

export interface RequestProofOptions extends ProofRequestConfig {
  connectionId: string
  proofRequestOptions: {
    name: string
    version: string
    requestedAttributes?: { [key: string]: ProofAttributeInfo }
    requestedPredicates?: { [key: string]: ProofPredicateInfo }
  }
}

export interface RequestProofProposalOptions {
  connectionId: string
  attributes: PresentationPreviewAttributeOptions[]
  predicates: PresentationPreviewPredicateOptions[]
  comment?: string
  autoAcceptProof?: AutoAcceptProof
}
