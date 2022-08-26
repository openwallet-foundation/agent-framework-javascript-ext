import type { Agent, BaseRecord } from '@aries-framework/core'
import type { AsyncThunkPayloadCreator } from '@reduxjs/toolkit'

import { createAsyncThunk } from '@reduxjs/toolkit'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Constructor<T = unknown> = new (...args: any[]) => T
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Method<M> = M extends (...args: any) => any ? M : never
type ClassMethodParameters<T, M> = T extends Constructor
  ? M extends keyof InstanceType<T>
    ? Parameters<Method<InstanceType<T>[M]>>
    : never
  : M extends keyof T
  ? Parameters<Method<T[M]>>
  : never
interface AgentThunkApiConfig {
  extra: {
    agent: Agent
  }
}

function createAsyncAgentThunk<Returned, ThunkArg = void>(
  typePrefix: string,
  payloadCreator: AsyncThunkPayloadCreator<Returned, ThunkArg, AgentThunkApiConfig>
) {
  return createAsyncThunk<Returned, ThunkArg, AgentThunkApiConfig>(typePrefix, async (thunkArg, thunkApi) => {
    if (!thunkApi.extra.agent) return thunkApi.rejectWithValue('Agent not set')
    if (!thunkApi.extra.agent.isInitialized) return thunkApi.rejectWithValue('Agent not initialized, call agent.init()')
    return payloadCreator(thunkArg, thunkApi)
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type BaseRecordAny = BaseRecord<any, any, any>

type RecordConstructor<RecordType extends BaseRecordAny = BaseRecordAny> = Constructor<RecordType> & { type: string }

const isRecordType = <RecordType extends BaseRecordAny>(
  record: BaseRecord,
  expectedRecordType: RecordConstructor<RecordType>
): record is RecordType => {
  return record.type === expectedRecordType.type
}

export { createAsyncAgentThunk, isRecordType }

export type { AgentThunkApiConfig, ClassMethodParameters, RecordConstructor }
