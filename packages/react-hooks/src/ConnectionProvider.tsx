import type { RecordsState } from './recordUtils'
import type { Agent, DidExchangeState, ConnectionType } from '@aries-framework/core'
import type { PropsWithChildren } from 'react'

import { ConnectionRecord } from '@aries-framework/core'
import { useState, createContext, useContext, useEffect, useMemo } from 'react'
import * as React from 'react'

import {
  recordsAddedByType,
  recordsRemovedByType,
  recordsUpdatedByType,
  removeRecord,
  updateRecord,
  addRecord,
} from './recordUtils'

export type UseConnectionsOptions = {
  excludedTypes?: Array<ConnectionType | string>
  connectionState?: DidExchangeState
}

const ConnectionContext = createContext<RecordsState<ConnectionRecord> | undefined>(undefined)

/**
 * This method retrieves the connection context for the current agent.
 * From this you can access all connection records for the agent.
 * @param options options for useConnections hook, lets us filter out specific types and limit states
 * @returns a connection context containing information about the agents connections
 */
export const useConnections = (options: UseConnectionsOptions = {}) => {
  const connectionContext = useContext(ConnectionContext)

  let connections = connectionContext?.records
  connections = useMemo(() => {
    if (!connections) {
      throw new Error('useConnections must be used within a ConnectionContextProvider')
    }
    // do not filter if not filter options are provided to save on a loop
    if (!options.connectionState && !options.excludedTypes) return connections

    return connections.filter((record: ConnectionRecord) => {
      // By default we include this connection
      // Filter by state (if connectionState is defined)
      if (options.connectionState && options.connectionState !== record.state) return false

      // Exclude records with certain connection types (if defined)
      const recordTypes = record.connectionTypes as Array<ConnectionType | string> | null
      if (options.excludedTypes && recordTypes) {
        return recordTypes.some((connectionType) => !options.excludedTypes?.includes(connectionType))
      }
      return true
    })
  }, [connections, options.connectionState, options.excludedTypes])

  return { ...connectionContext, records: connections }
}

export const useConnectionById = (id: string): ConnectionRecord | undefined => {
  const { records: connections } = useConnections()
  return connections.find((c: ConnectionRecord) => c.id === id)
}

/**
 * @deprecated filtering by state can now be done by passing options to useConnections hook
 */
export const useConnectionByState = (state: DidExchangeState | DidExchangeState[]): ConnectionRecord[] => {
  const states = useMemo(() => (typeof state === 'string' ? [state] : state), [state])

  const { records: connections } = useConnections()

  const filteredConnections = useMemo(
    () =>
      connections.filter((r: ConnectionRecord) => {
        if (states.includes(r.state)) return r
      }),
    [connections]
  )
  return filteredConnections
}

/**
 * @deprecated filtering by state can now be done by passing options to useConnections hook
 */
export const useConnectionNotInState = (state: DidExchangeState | DidExchangeState[]): ConnectionRecord[] => {
  const states = useMemo(() => (typeof state === 'string' ? [state] : state), [state])

  const { records: connections } = useConnections()

  const filteredConnections = useMemo(
    () =>
      connections.filter((r: ConnectionRecord) => {
        if (!states.includes(r.state)) return r
      }),
    [connections]
  )
  return filteredConnections
}

interface Props {
  agent: Agent | undefined
}

const ConnectionProvider: React.FC<PropsWithChildren<Props>> = ({ agent, children }) => {
  const [state, setState] = useState<RecordsState<ConnectionRecord>>({
    records: [],
    loading: true,
  })

  const setInitialState = async () => {
    if (agent) {
      const records = await agent.connections.getAll()
      setState({ records, loading: false })
    }
  }

  useEffect(() => {
    setInitialState()
  }, [agent])

  useEffect(() => {
    if (!state.loading) {
      const connectionAdded$ = recordsAddedByType(agent, ConnectionRecord).subscribe((record) =>
        setState(addRecord(record, state))
      )

      const connectionUpdated$ = recordsUpdatedByType(agent, ConnectionRecord).subscribe((record) =>
        setState(updateRecord(record, state))
      )

      const connectionRemoved$ = recordsRemovedByType(agent, ConnectionRecord).subscribe((record) =>
        setState(removeRecord(record, state))
      )

      return () => {
        connectionAdded$.unsubscribe()
        connectionUpdated$.unsubscribe()
        connectionRemoved$.unsubscribe()
      }
    }
  }, [state, agent])

  return <ConnectionContext.Provider value={state}>{children}</ConnectionContext.Provider>
}

export default ConnectionProvider
