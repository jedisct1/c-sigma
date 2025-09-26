#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "linear_relation.h"
#include <stddef.h>
#include <stdint.h>

// Serialization API for Sigma protocol proofs
// Implements spec section 1.1 serialize/deserialize functions

// Error codes
#define SERIALIZE_OK               0
#define SERIALIZE_ERROR_NULL_INPUT -1
#define SERIALIZE_ERROR_INVALID    -2
#define SERIALIZE_ERROR_BAD_LENGTH -3

// Serialize commitment (array of group elements)
// output: buffer for serialized data (must be pre-allocated: num_elements * POINT_BYTES)
// commitment: array of group elements
// num_elements: number of elements to serialize
int serialize_commitment(uint8_t* output, const uint8_t* commitment, size_t num_elements);

// Deserialize commitment
// commitment: output buffer (must be pre-allocated: num_elements * POINT_BYTES)
// data: serialized data
// data_len: length of data
// num_elements: expected number of elements
int deserialize_commitment(uint8_t* commitment, const uint8_t* data, size_t data_len,
                           size_t num_elements);

// Serialize response (array of scalars)
// output: buffer for serialized data (must be pre-allocated: num_scalars * SCALAR_BYTES)
// response: array of scalars
// num_scalars: number of scalars to serialize
int serialize_response(uint8_t* output, const uint8_t* response, size_t num_scalars);

// Deserialize response
// response: output buffer (must be pre-allocated: num_scalars * SCALAR_BYTES)
// data: serialized data
// data_len: length of data
// num_scalars: expected number of scalars
int deserialize_response(uint8_t* response, const uint8_t* data, size_t data_len,
                         size_t num_scalars);

// Serialize complete proof (commitment + response)
// output: buffer for serialized proof
// commitment: commitment array
// num_commitment_elements: number of group elements in commitment
// response: response array
// num_response_scalars: number of scalars in response
// Returns: number of bytes written, or negative error code
int serialize_proof(uint8_t* output, const uint8_t* commitment, size_t num_commitment_elements,
                    const uint8_t* response, size_t num_response_scalars);

// Deserialize complete proof (commitment + response)
// commitment: output buffer for commitment
// num_commitment_elements: expected number of group elements
// response: output buffer for response
// num_response_scalars: expected number of scalars
// data: serialized proof
// data_len: length of proof data
int deserialize_proof(uint8_t* commitment, size_t num_commitment_elements, uint8_t* response,
                      size_t num_response_scalars, const uint8_t* data, size_t data_len);

// Calculate proof size in bytes
static inline size_t
proof_size(size_t num_commitment_elements, size_t num_response_scalars)
{
    return num_commitment_elements * POINT_BYTES + num_response_scalars * SCALAR_BYTES;
}

#endif
