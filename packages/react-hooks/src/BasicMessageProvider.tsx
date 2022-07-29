import type { RecordsState } from './recordUtils'
import type { Agent } from '@aries-framework/core'
import type { PropsWithChildren } from 'react'

import { BasicMessageRecord } from '@aries-framework/core'
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

const BasicMessageContext = createContext<RecordsState<BasicMessageRecord> | undefined>(undefined)

export const useBasicMessages = () => {
  const basicMessageContext = useContext(BasicMessageContext)
  if (!basicMessageContext) {
    throw new Error('useBasicMessages must be used within a BasicMessageContextProvider')
  }
  return basicMessageContext
}

export const useBasicMessagesByConnectionId = (connectionId: string): BasicMessageRecord[] => {
  const { records: basicMessages } = useBasicMessages()
  const messages = useMemo(
    () => basicMessages.filter((m: BasicMessageRecord) => m.connectionId === connectionId),
    [basicMessages, connectionId]
  )
  return messages
}

interface Props {
  agent: Agent | undefined
}

const BasicMessageProvider: React.FC<PropsWithChildren<Props>> = ({ agent, children }) => {
  const [state, setState] = useState<RecordsState<BasicMessageRecord>>({
    records: [],
    loading: true,
  })

  const setInitialState = async () => {
    if (agent) {
      const records = await agent.basicMessages.findAllByQuery({})
      setState({ records, loading: false })
    }
  }

  useEffect(() => {
    setInitialState()
  }, [agent])

  useEffect(() => {
    if (!state.loading) {
      const basicMessageAdded$ = recordsAddedByType(agent, BasicMessageRecord).subscribe((record) =>
        setState(addRecord(record, state))
      )

      const basicMessageUpdated$ = recordsUpdatedByType(agent, BasicMessageRecord).subscribe((record) =>
        setState(updateRecord(record, state))
      )

      const basicMessageRemoved$ = recordsRemovedByType(agent, BasicMessageRecord).subscribe((record) =>
        setState(removeRecord(record, state))
      )

      return () => {
        basicMessageAdded$?.unsubscribe()
        basicMessageUpdated$?.unsubscribe()
        basicMessageRemoved$?.unsubscribe()
      }
    }
  }, [state, agent])

  return <BasicMessageContext.Provider value={state}>{children}</BasicMessageContext.Provider>
}

export default BasicMessageProvider
