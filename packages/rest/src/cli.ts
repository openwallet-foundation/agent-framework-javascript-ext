import type { InboundTransport, Transports, CredoRestConfig } from './cliAgent'
import type { AskarWalletPostgresStorageConfig } from '@credo-ts/askar'

import yargs from 'yargs'

import { runRestAgent } from './cliAgent'

const parsed = yargs
  .command('start', 'Start Credo Rest agent')
  .option('label', {
    alias: 'l',
    string: true,
    demandOption: true,
  })
  .option('wallet-id', {
    string: true,
    demandOption: true,
  })
  .option('wallet-key', {
    string: true,
    demandOption: true,
  })
  .option('indy-ledger', {
    array: true,
    default: [],
    coerce: (items: unknown[]) => items.map((i) => (typeof i === 'string' ? JSON.parse(i) : i)),
  })
  .option('endpoint', {
    array: true,
  })
  .option('log-level', {
    number: true,
    default: 3,
  })
  .option('use-did-sov-prefix-where-allowed', {
    boolean: true,
    default: false,
  })
  .option('use-did-key-in-protocols', {
    boolean: true,
    default: true,
  })
  .option('outbound-transport', {
    default: [],
    choices: ['http', 'ws'],
    array: true,
  })
  .option('--multi-tenant', {
    boolean: true,
    default: false,
    describe:
      'Start the agent as a multi-tenant agent. Once enabled, all operations (except tenant management) must be performed under a specific tenant. Tenants can be created in the tenants controller (POST /tenants, see swagger UI), and the scope for a specific tenant can be set using the x-tenant-id header.',
  })
  .option('inbound-transport', {
    array: true,
    default: [],
    coerce: (input: string[]) => {
      // Configured using config object
      if (typeof input[0] === 'object') return input
      if (input.length % 2 !== 0) {
        throw new Error(
          'Inbound transport should be specified as transport port pairs (e.g. --inbound-transport http 5000 ws 5001)',
        )
      }

      return input.reduce<Array<InboundTransport>>((transports, item, index) => {
        const isEven = index % 2 === 0
        // isEven means it is the transport
        // transport port transport port
        const isTransport = isEven

        if (isTransport) {
          transports.push({
            transport: item as Transports,
            port: Number(input[index + 1]),
          })
        }

        return transports
      }, [])
    },
  })
  .option('auto-accept-connections', {
    boolean: true,
    default: false,
  })
  .option('auto-accept-credentials', {
    choices: ['always', 'never', 'contentApproved'],
    default: 'never',
  })
  .option('auto-accept-mediation-requests', {
    boolean: true,
    default: false,
  })
  .option('auto-accept-proofs', {
    choices: ['always', 'never', 'contentApproved'],
    default: 'never',
  })
  .option('auto-update-storage-on-startup', {
    boolean: true,
    default: true,
  })
  .option('connection-image-url', {
    string: true,
  })
  .option('webhook-url', {
    string: true,
  })
  .option('admin-port', {
    number: true,
    demandOption: true,
  })
  .option('storage-type', {
    choices: ['sqlite', 'postgres'],
    default: 'sqlite',
  })
  .option('postgres-host', {
    string: true,
  })
  .option('postgres-username', {
    string: true,
  })
  .option('postgres-password', {
    string: true,
  })
  .check((argv) => {
    if (
      argv['storage-type'] === 'postgres' &&
      (!argv['postgres-host'] || !argv['postgres-username'] || !argv['postgres-password'])
    ) {
      throw new Error(
        "--postgres-host, --postgres-username, and postgres-password are required when setting --storage-type to 'postgres'",
      )
    }
  })
  .config()
  .env('CREDO_REST')
  .parseSync()

export async function runCliServer() {
  await runRestAgent({
    label: parsed.label,
    walletConfig: {
      id: parsed['wallet-id'],
      key: parsed['wallet-key'],
      storage:
        parsed['storage-type'] === 'sqlite'
          ? {}
          : ({
              type: 'postgres',
              config: {
                host: parsed['postgres-host'] as string,
              },
              credentials: {
                account: parsed['postgres-username'] as string,
                password: parsed['postgres-password'] as string,
              },
            } satisfies AskarWalletPostgresStorageConfig),
    },
    indyLedgers: parsed['indy-ledger'],
    endpoints: parsed.endpoint,
    autoAcceptConnections: parsed['auto-accept-connections'],
    autoAcceptCredentials: parsed['auto-accept-credentials'],
    autoAcceptProofs: parsed['auto-accept-proofs'],
    autoUpdateStorageOnStartup: parsed['auto-update-storage-on-startup'],
    autoAcceptMediationRequests: parsed['auto-accept-mediation-requests'],
    useDidKeyInProtocols: parsed['use-did-key-in-protocols'],
    useDidSovPrefixWhereAllowed: parsed['use-legacy-did-sov-prefix'],
    logLevel: parsed['log-level'],
    inboundTransports: parsed['inbound-transport'],
    outboundTransports: parsed['outbound-transport'],
    connectionImageUrl: parsed['connection-image-url'],
    webhookUrl: parsed['webhook-url'],
    adminPort: parsed['admin-port'],
    multiTenant: parsed['multi-tenant'],
  } as CredoRestConfig)
}
