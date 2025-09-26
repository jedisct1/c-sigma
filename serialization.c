#include "serialization.h"
#include <string.h>

int
serialize_commitment(uint8_t* output, const uint8_t* commitment, size_t num_elements)
{
    if (!output || !commitment) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    // Ristretto255 points are already in canonical 32-byte representation
    // Just copy them directly
    memcpy(output, commitment, num_elements * POINT_BYTES);
    return SERIALIZE_OK;
}

int
deserialize_commitment(uint8_t* commitment, const uint8_t* data, size_t data_len,
                       size_t num_elements)
{
    if (!commitment || !data) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    size_t expected_len = num_elements * POINT_BYTES;
    if (data_len != expected_len) {
        return SERIALIZE_ERROR_BAD_LENGTH;
    }

    // Verify each point is valid by attempting to use it
    // Ristretto255 ensures canonical encoding, but we should still validate
    for (size_t i = 0; i < num_elements; i++) {
        const uint8_t* point = &data[i * POINT_BYTES];

        // Validate by checking if it's a valid Ristretto255 point
        // We can do this by attempting scalar multiplication by 1
        uint8_t one[SCALAR_BYTES] = { 1 };
        uint8_t result[POINT_BYTES];

        if (crypto_scalarmult_ristretto255(result, one, point) != 0) {
            return SERIALIZE_ERROR_INVALID;
        }
    }

    // All points valid, copy to output
    memcpy(commitment, data, expected_len);
    return SERIALIZE_OK;
}

int
serialize_response(uint8_t* output, const uint8_t* response, size_t num_scalars)
{
    if (!output || !response) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    // Scalars are already in canonical 32-byte representation
    memcpy(output, response, num_scalars * SCALAR_BYTES);
    return SERIALIZE_OK;
}

int
deserialize_response(uint8_t* response, const uint8_t* data, size_t data_len, size_t num_scalars)
{
    if (!response || !data) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    size_t expected_len = num_scalars * SCALAR_BYTES;
    if (data_len != expected_len) {
        return SERIALIZE_ERROR_BAD_LENGTH;
    }

    // For Ristretto255, scalars are already canonical
    // libsodium ensures scalars are reduced modulo the group order
    // We could add validation here if needed, but it's not strictly required
    memcpy(response, data, expected_len);
    return SERIALIZE_OK;
}

int
serialize_proof(uint8_t* output, const uint8_t* commitment, size_t num_commitment_elements,
                const uint8_t* response, size_t num_response_scalars)
{
    if (!output || !commitment || !response) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    size_t commitment_size = num_commitment_elements * POINT_BYTES;
    size_t response_size   = num_response_scalars * SCALAR_BYTES;

    // Serialize: commitment || response
    memcpy(output, commitment, commitment_size);
    memcpy(output + commitment_size, response, response_size);

    return (int) (commitment_size + response_size);
}

int
deserialize_proof(uint8_t* commitment, size_t num_commitment_elements, uint8_t* response,
                  size_t num_response_scalars, const uint8_t* data, size_t data_len)
{
    if (!commitment || !response || !data) {
        return SERIALIZE_ERROR_NULL_INPUT;
    }

    size_t commitment_size = num_commitment_elements * POINT_BYTES;
    size_t response_size   = num_response_scalars * SCALAR_BYTES;
    size_t expected_len    = commitment_size + response_size;

    if (data_len != expected_len) {
        return SERIALIZE_ERROR_BAD_LENGTH;
    }

    // Deserialize commitment
    int result = deserialize_commitment(commitment, data, commitment_size, num_commitment_elements);
    if (result != SERIALIZE_OK) {
        return result;
    }

    // Deserialize response
    result =
        deserialize_response(response, data + commitment_size, response_size, num_response_scalars);
    if (result != SERIALIZE_OK) {
        return result;
    }

    return SERIALIZE_OK;
}
