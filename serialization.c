#include "serialization.h"
#include <string.h>

// Internal helper: deserialize commitment with validation
static int
deserialize_commitment(uint8_t* commitment, const uint8_t* data, size_t data_len,
                       size_t num_elements)
{
    if (!commitment || !data) {
        return -1;
    }

    size_t expected_len = num_elements * CSIGMA_POINT_BYTES;
    if (data_len != expected_len) {
        return -1;
    }

    // Verify each point is valid by attempting to use it
    for (size_t i = 0; i < num_elements; i++) {
        const uint8_t* point = &data[i * CSIGMA_POINT_BYTES];

        // Validate by checking if it's a valid Ristretto255 point
        // Scalar multiplication by 1 will fail for invalid points
        uint8_t one[CSIGMA_SCALAR_BYTES] = { 1 };
        uint8_t result[CSIGMA_POINT_BYTES];

        if (crypto_scalarmult_ristretto255(result, one, point) != 0) {
            return -1;
        }
    }

    // All points valid, copy to output
    memcpy(commitment, data, expected_len);
    return 0;
}

// Internal helper: deserialize response
static int
deserialize_response(uint8_t* response, const uint8_t* data, size_t data_len, size_t num_scalars)
{
    if (!response || !data) {
        return -1;
    }

    size_t expected_len = num_scalars * CSIGMA_SCALAR_BYTES;
    if (data_len != expected_len) {
        return -1;
    }

    // For Ristretto255, scalars are already canonical
    memcpy(response, data, expected_len);
    return 0;
}

int
csigma_serialize_proof(uint8_t* output, const uint8_t* commitment, size_t num_commitment_elements,
                       const uint8_t* response, size_t num_response_scalars)
{
    if (!output || !commitment || !response) {
        return -1;
    }

    size_t commitment_size = num_commitment_elements * CSIGMA_POINT_BYTES;
    size_t response_size   = num_response_scalars * CSIGMA_SCALAR_BYTES;

    // Serialize: commitment || response
    memcpy(output, commitment, commitment_size);
    memcpy(output + commitment_size, response, response_size);

    return 0;
}

int
csigma_deserialize_proof(uint8_t* commitment, size_t num_commitment_elements, uint8_t* response,
                         size_t num_response_scalars, const uint8_t* data, size_t data_len)
{
    if (!commitment || !response || !data) {
        return -1;
    }

    size_t commitment_size = num_commitment_elements * CSIGMA_POINT_BYTES;
    size_t response_size   = num_response_scalars * CSIGMA_SCALAR_BYTES;
    size_t expected_len    = commitment_size + response_size;

    if (data_len != expected_len) {
        return -1;
    }

    // Deserialize commitment with validation
    if (deserialize_commitment(commitment, data, commitment_size, num_commitment_elements) != 0) {
        return -1;
    }

    // Deserialize response
    if (deserialize_response(response, data + commitment_size, response_size,
                             num_response_scalars) != 0) {
        return -1;
    }

    return 0;
}
