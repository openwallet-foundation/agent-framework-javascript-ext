import type { SerializedInstance } from '../../types'
import type { SerializedError } from '@reduxjs/toolkit'

import { ProofRecord, JsonTransformer } from '@aries-framework/core'
import { createSlice } from '@reduxjs/toolkit'

import {
  addRecord,
  addRecordInState,
  updateRecord,
  updateRecordInState,
  removeRecord,
  removeRecordInState,
} from '../../recordListener'

import { ProofsThunks } from './proofsThunks'

interface ProofsState {
  proofs: {
    records: SerializedInstance<ProofRecord>[]
    isLoading: boolean
  }
  error: null | SerializedError
}

const initialState: ProofsState = {
  proofs: {
    records: [],
    isLoading: false,
  },
  error: null,
}

const proofsSlice = createSlice({
  name: 'proofs',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      // getAllProofs
      .addCase(ProofsThunks.getAllProofs.pending, (state) => {
        state.proofs.isLoading = true
      })
      .addCase(ProofsThunks.getAllProofs.rejected, (state, action) => {
        state.proofs.isLoading = false
        state.error = action.error
      })
      .addCase(ProofsThunks.getAllProofs.fulfilled, (state, action) => {
        state.proofs.isLoading = false
        state.proofs.records = action.payload.map((p) => JsonTransformer.toJSON(p))
      })
      // record events
      .addCase(addRecord, (state, action) => addRecordInState(ProofRecord, state.proofs.records, action.payload))
      .addCase(removeRecord, (state, action) => removeRecordInState(ProofRecord, state.proofs.records, action.payload))
      .addCase(updateRecord, (state, action) => updateRecordInState(ProofRecord, state.proofs.records, action.payload))
  },
})

export { proofsSlice }

export type { ProofsState }
