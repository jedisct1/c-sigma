#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "csigma.h"

// Serialization API for Sigma protocol proofs
// Implements spec section 1.1 serialize/deserialize functions

// All functions return 0 on success, -1 on error (consistent with other APIs)

// Serialize complete proof (commitment + response)
// output: buffer for serialized proof (must be pre-allocated)
// commitment: commitment array
// num_commitment_elements: number of group elements in commitment
// response: response array
// num_response_scalars: number of scalars in response
// Returns 0 on success, -1 on error
int csigma_serialize_proof(uint8_t* output, const uint8_t* commitment,
                           size_t num_commitment_elements, const uint8_t* response,
                           size_t num_response_scalars);

// Deserialize complete proof (commitment + response)
// commitment: output buffer for commitment (must be pre-allocated)
// num_commitment_elements: expected number of group elements
// response: output buffer for response (must be pre-allocated)
// num_response_scalars: expected number of scalars
// data: serialized proof
// data_len: length of proof data
// Returns 0 on success, -1 on error
int csigma_deserialize_proof(uint8_t* commitment, size_t num_commitment_elements, uint8_t* response,
                             size_t num_response_scalars, const uint8_t* data, size_t data_len);

// Calculate proof size in bytes (helper function)
static inline size_t
csigma_proof_size(size_t num_commitment_elements, size_t num_response_scalars)
{
    return num_commitment_elements * CSIGMA_POINT_BYTES +
           num_response_scalars * CSIGMA_SCALAR_BYTES;
}

#endif
