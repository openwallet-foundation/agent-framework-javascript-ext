import type { OpenId4VcIssuanceSessionCreateOfferSdJwtCredentialOptions } from '../controllers/openid4vc/issuance-sessions/OpenId4VcIssuanceSessionsControllerTypes'
import type { AnonCredsRegistry } from '@credo-ts/anoncreds'
import type { NetworkConfig as CheqdNetworkConfig } from '@credo-ts/cheqd/build/CheqdModuleConfig'
import type { Agent, AutoAcceptCredential, AutoAcceptProof } from '@credo-ts/core'
import type { IndyVdrPoolConfig } from '@credo-ts/indy-vdr'
import type { TenantAgent } from '@credo-ts/tenants/build/TenantAgent'

import {
  AnonCredsCredentialFormatService,
  AnonCredsProofFormatService,
  V1CredentialProtocol,
  AnonCredsModule,
  LegacyIndyCredentialFormatService,
  LegacyIndyProofFormatService,
  V1ProofProtocol,
} from '@credo-ts/anoncreds'
import { AskarModule, AskarMultiWalletDatabaseScheme } from '@credo-ts/askar'
import { CheqdModule, CheqdDidResolver, CheqdDidRegistrar, CheqdAnonCredsRegistry } from '@credo-ts/cheqd'
import {
  V2CredentialProtocol,
  V2ProofProtocol,
  ConnectionsModule,
  CredentialsModule,
  MediatorModule,
  ProofsModule,
  DidsModule,
  KeyDidRegistrar,
  JwkDidRegistrar,
  PeerDidRegistrar,
  WebDidResolver,
  KeyDidResolver,
  JwkDidResolver,
  PeerDidResolver,
} from '@credo-ts/core'
import {
  IndyVdrAnonCredsRegistry,
  IndyVdrModule,
  IndyVdrIndyDidResolver,
  IndyVdrSovDidResolver,
  IndyVdrIndyDidRegistrar,
} from '@credo-ts/indy-vdr'
import { OpenId4VcIssuerModule, OpenId4VcHolderModule, OpenId4VcVerifierModule } from '@credo-ts/openid4vc'
import { TenantsModule } from '@credo-ts/tenants'
import { anoncreds } from '@hyperledger/anoncreds-nodejs'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { indyVdr } from '@hyperledger/indy-vdr-nodejs'

export type { CheqdNetworkConfig }
type ModulesWithoutTenants = Omit<ReturnType<typeof getAgentModules>, 'tenants'>

export type RestRootAgent = Agent<ModulesWithoutTenants>
export type RestRootAgentWithTenants = Agent<ModulesWithoutTenants & { tenants: TenantsModule<ModulesWithoutTenants> }>
export type RestTenantAgent = TenantAgent<ModulesWithoutTenants>
export type RestAgent = RestRootAgent | RestTenantAgent | RestRootAgentWithTenants

export function getAgentModules(options: {
  autoAcceptConnections: boolean
  autoAcceptProofs: AutoAcceptProof
  autoAcceptCredentials: AutoAcceptCredential
  autoAcceptMediationRequests: boolean
  indyLedgers?: [IndyVdrPoolConfig, ...IndyVdrPoolConfig[]]
  cheqdLedgers?: CheqdNetworkConfig[]
  extraAnonCredsRegistries?: AnonCredsRegistry[]
  multiTenant: boolean
  baseUrl: string
}) {
  const legacyIndyCredentialFormatService = new LegacyIndyCredentialFormatService()
  const legacyIndyProofFormatService = new LegacyIndyProofFormatService()

  const baseUrlWithoutSlash = options.baseUrl.endsWith('/') ? options.baseUrl.slice(0, -1) : options.baseUrl

  const baseModules = {
    connections: new ConnectionsModule({
      autoAcceptConnections: options.autoAcceptConnections,
    }),
    proofs: new ProofsModule({
      autoAcceptProofs: options.autoAcceptProofs,
      proofProtocols: [
        new V1ProofProtocol({
          indyProofFormat: legacyIndyProofFormatService,
        }),
        new V2ProofProtocol({
          proofFormats: [legacyIndyProofFormatService, new AnonCredsProofFormatService()],
        }),
      ],
    }),
    credentials: new CredentialsModule({
      autoAcceptCredentials: options.autoAcceptCredentials,
      credentialProtocols: [
        new V1CredentialProtocol({
          indyCredentialFormat: legacyIndyCredentialFormatService,
        }),
        new V2CredentialProtocol({
          credentialFormats: [legacyIndyCredentialFormatService, new AnonCredsCredentialFormatService()],
        }),
      ],
    }),
    anoncreds: new AnonCredsModule({
      registries: (options.extraAnonCredsRegistries ?? []) as [AnonCredsRegistry],
      anoncreds,
    }),
    askar: new AskarModule({
      ariesAskar,
      multiWalletDatabaseScheme: AskarMultiWalletDatabaseScheme.ProfilePerWallet,
    }),
    mediator: new MediatorModule({
      autoAcceptMediationRequests: options.autoAcceptMediationRequests,
    }),
    dids: new DidsModule({
      registrars: [new KeyDidRegistrar(), new JwkDidRegistrar(), new PeerDidRegistrar()],
      resolvers: [new WebDidResolver(), new KeyDidResolver(), new JwkDidResolver(), new PeerDidResolver()],
    }),
    openId4VcIssuer: new OpenId4VcIssuerModule({
      baseUrl: `${baseUrlWithoutSlash}/oid4vci`,
      endpoints: {
        credential: {
          credentialRequestToCredentialMapper: ({ issuanceSession, holderBinding, credentialsSupported }) => {
            const credentials = issuanceSession.issuanceMetadata
              ?.credentials as OpenId4VcIssuanceSessionCreateOfferSdJwtCredentialOptions[]
            if (!credentials) throw new Error('Not implemented')

            const requestedIds = credentialsSupported.map((c) => c.id).filter((id): id is string => id !== undefined)
            const firstCredential = credentials.find((c) => requestedIds.includes(c.credentialSupportedId))
            if (!firstCredential) throw new Error('Not implemented')

            if (firstCredential.format === 'vc+sd-jwt') {
              return {
                credentialSupportedId: firstCredential.credentialSupportedId,
                format: 'vc+sd-jwt',
                issuer: firstCredential.issuer,
                holder: holderBinding,
                payload: firstCredential.payload,
                // Type in credo is wrong
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                disclosureFrame: firstCredential.disclosureFrame as any,
                hashingAlgorithm: 'sha-256',
              }
            }

            throw new Error('Not implemented')
          },
        },
      },
    }),
    openId4VcHolder: new OpenId4VcHolderModule(),
    openId4VcVerifier: new OpenId4VcVerifierModule({
      baseUrl: `${baseUrlWithoutSlash}/siop`,
    }),
  } as const

  const modules: typeof baseModules & {
    tenants?: TenantsModule<typeof baseModules>
    indyVdr?: IndyVdrModule
    cheqd?: CheqdModule
  } = baseModules

  if (options.multiTenant) {
    modules.tenants = new TenantsModule({
      sessionLimit: Infinity,
    })
  }

  // Register indy module and related resolvers/registrars
  if (options.indyLedgers) {
    modules.indyVdr = new IndyVdrModule({
      indyVdr,
      networks: options.indyLedgers,
    })
    modules.dids.config.addRegistrar(new IndyVdrIndyDidRegistrar())
    modules.dids.config.addResolver(new IndyVdrIndyDidResolver())
    modules.dids.config.addResolver(new IndyVdrSovDidResolver())
    modules.anoncreds.config.registries.push(new IndyVdrAnonCredsRegistry())
  }

  // Register cheqd module and related resolvers/registrars
  if (options.cheqdLedgers) {
    modules.cheqd = new CheqdModule({
      networks: options.cheqdLedgers,
    })
    modules.dids.config.addRegistrar(new CheqdDidRegistrar())
    modules.dids.config.addResolver(new CheqdDidResolver())
    modules.anoncreds.config.registries.push(new CheqdAnonCredsRegistry())
  }

  return modules
}
