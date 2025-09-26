#include "linear_relation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initial capacity for dynamic arrays
#define INITIAL_TERMS_CAPACITY       4
#define INITIAL_CONSTRAINTS_CAPACITY 4
#define INITIAL_ELEMENTS_CAPACITY    8

// ============================================================================
// Linear Combination Operations
// ============================================================================

void
linear_combination_init(linear_combination_t* lc)
{
    lc->scalar_indices  = malloc(INITIAL_TERMS_CAPACITY * sizeof(int));
    lc->element_indices = malloc(INITIAL_TERMS_CAPACITY * sizeof(int));
    lc->num_terms       = 0;
    lc->capacity        = INITIAL_TERMS_CAPACITY;
}

void
linear_combination_add_term(linear_combination_t* lc, int scalar_idx, int element_idx)
{
    if (lc->num_terms >= lc->capacity) {
        lc->capacity *= 2;
        lc->scalar_indices  = realloc(lc->scalar_indices, lc->capacity * sizeof(int));
        lc->element_indices = realloc(lc->element_indices, lc->capacity * sizeof(int));
    }
    lc->scalar_indices[lc->num_terms]  = scalar_idx;
    lc->element_indices[lc->num_terms] = element_idx;
    lc->num_terms++;
}

void
linear_combination_destroy(linear_combination_t* lc)
{
    free(lc->scalar_indices);
    free(lc->element_indices);
    lc->scalar_indices  = NULL;
    lc->element_indices = NULL;
    lc->num_terms       = 0;
    lc->capacity        = 0;
}

// ============================================================================
// Linear Map Operations
// ============================================================================

void
linear_map_init(linear_map_t* map)
{
    map->combinations         = malloc(INITIAL_CONSTRAINTS_CAPACITY * sizeof(linear_combination_t));
    map->group_elements       = malloc(INITIAL_ELEMENTS_CAPACITY * POINT_BYTES);
    map->num_constraints      = 0;
    map->num_scalars          = 0;
    map->num_elements         = 0;
    map->constraints_capacity = INITIAL_CONSTRAINTS_CAPACITY;
    map->elements_capacity    = INITIAL_ELEMENTS_CAPACITY;
}

void
linear_map_destroy(linear_map_t* map)
{
    for (size_t i = 0; i < map->num_constraints; i++) {
        linear_combination_destroy(&map->combinations[i]);
    }
    free(map->combinations);
    free(map->group_elements);
    map->combinations   = NULL;
    map->group_elements = NULL;
}

// Evaluate linear map: output[i] = sum_j(scalars[j] * elements[k])
// where the sum is over terms in combinations[i]
int
linear_map_eval(const linear_map_t* map, const uint8_t* scalars, uint8_t* output)
{
    for (size_t i = 0; i < map->num_constraints; i++) {
        const linear_combination_t* lc = &map->combinations[i];

        // Start with identity element
        // For Ristretto255, we compute the first term, then accumulate the rest
        uint8_t result[POINT_BYTES];
        bool    first_term = true;

        // Accumulate: result = sum of scalars[j] * elements[k]
        for (size_t j = 0; j < lc->num_terms; j++) {
            int      scalar_idx  = lc->scalar_indices[j];
            int      element_idx = lc->element_indices[j];
            uint8_t* element     = &map->group_elements[element_idx * POINT_BYTES];

            // Compute term = scalar * element
            uint8_t term[POINT_BYTES];
            if (crypto_scalarmult_ristretto255(term, &scalars[scalar_idx * SCALAR_BYTES],
                                               element) != 0) {
                return -1; // Invalid point
            }

            if (first_term) {
                memcpy(result, term, POINT_BYTES);
                first_term = false;
            } else {
                // result += term
                uint8_t new_result[POINT_BYTES];
                if (crypto_core_ristretto255_add(new_result, result, term) != 0) {
                    return -1; // Addition failed
                }
                memcpy(result, new_result, POINT_BYTES);
            }
        }

        // If no terms, this is an error (empty linear combination)
        if (first_term) {
            return -1;
        }

        memcpy(&output[i * POINT_BYTES], result, POINT_BYTES);
    }
    return 0;
}

// ============================================================================
// Linear Relation Builder API
// ============================================================================

void
linear_relation_init(linear_relation_t* relation)
{
    linear_map_init(&relation->map);
    relation->image = NULL;
}

void
linear_relation_destroy(linear_relation_t* relation)
{
    linear_map_destroy(&relation->map);
    free(relation->image);
    relation->image = NULL;
}

int
linear_relation_allocate_scalars(linear_relation_t* relation, size_t n)
{
    int base_index = (int) relation->map.num_scalars;
    relation->map.num_scalars += n;
    return base_index;
}

int
linear_relation_allocate_elements(linear_relation_t* relation, size_t n)
{
    linear_map_t* map        = &relation->map;
    int           base_index = (int) map->num_elements;

    // Resize group_elements array if needed
    while (map->num_elements + n > map->elements_capacity) {
        map->elements_capacity *= 2;
        map->group_elements = realloc(map->group_elements, map->elements_capacity * POINT_BYTES);
    }

    map->num_elements += n;
    return base_index;
}

void
linear_relation_set_element(linear_relation_t* relation, int index,
                            const uint8_t element[POINT_BYTES])
{
    memcpy(&relation->map.group_elements[index * POINT_BYTES], element, POINT_BYTES);
}

void
linear_relation_append_equation(linear_relation_t* relation, int lhs, const int* rhs_scalar_indices,
                                const int* rhs_element_indices, size_t num_terms)
{
    linear_map_t* map = &relation->map;

    // Resize combinations array if needed
    if (map->num_constraints >= map->constraints_capacity) {
        map->constraints_capacity *= 2;
        map->combinations =
            realloc(map->combinations, map->constraints_capacity * sizeof(linear_combination_t));
    }

    // Initialize new linear combination
    linear_combination_t* lc = &map->combinations[map->num_constraints];
    linear_combination_init(lc);

    // Add all terms
    for (size_t i = 0; i < num_terms; i++) {
        linear_combination_add_term(lc, rhs_scalar_indices[i], rhs_element_indices[i]);
    }

    map->num_constraints++;

    // Resize image array if needed
    relation->image = realloc(relation->image, map->num_constraints * POINT_BYTES);
}

// ============================================================================
// General Sigma Protocol Interface
// ============================================================================

void
prover_state_init(prover_state_t* state, size_t num_scalars)
{
    state->num_scalars = num_scalars;
    state->witness     = malloc(num_scalars * SCALAR_BYTES);
    state->nonces      = malloc(num_scalars * SCALAR_BYTES);
}

void
prover_state_destroy(prover_state_t* state)
{
    sodium_memzero(state->witness, state->num_scalars * SCALAR_BYTES);
    sodium_memzero(state->nonces, state->num_scalars * SCALAR_BYTES);
    free(state->witness);
    free(state->nonces);
    state->witness     = NULL;
    state->nonces      = NULL;
    state->num_scalars = 0;
}

// Prover commit phase (spec section 2.2.2.1)
int
prover_commit(const linear_relation_t* relation, const uint8_t* witness, uint8_t* commitment,
              prover_state_t* state)
{
    size_t num_scalars = relation->map.num_scalars;

    // Initialize prover state
    prover_state_init(state, num_scalars);

    // Copy witness
    memcpy(state->witness, witness, num_scalars * SCALAR_BYTES);

    // Generate random nonces
    for (size_t i = 0; i < num_scalars; i++) {
        crypto_core_ristretto255_scalar_random(&state->nonces[i * SCALAR_BYTES]);
    }

    // Compute commitment = linear_map(nonces)
    if (linear_map_eval(&relation->map, state->nonces, commitment) != 0) {
        prover_state_destroy(state);
        return -1;
    }

    return 0;
}

// Prover response phase (spec section 2.2.2.2)
void
prover_response(const prover_state_t* state, const uint8_t challenge[SCALAR_BYTES],
                uint8_t* response)
{
    // response[i] = nonces[i] + witness[i] * challenge
    for (size_t i = 0; i < state->num_scalars; i++) {
        const uint8_t* nonce   = &state->nonces[i * SCALAR_BYTES];
        const uint8_t* witness = &state->witness[i * SCALAR_BYTES];
        uint8_t*       resp    = &response[i * SCALAR_BYTES];

        uint8_t c_times_witness[SCALAR_BYTES];
        crypto_core_ristretto255_scalar_mul(c_times_witness, challenge, witness);
        crypto_core_ristretto255_scalar_add(resp, nonce, c_times_witness);
    }
}

// Verifier algorithm (spec section 2.2.3)
bool
verifier(const linear_relation_t* relation, const uint8_t* commitment,
         const uint8_t challenge[SCALAR_BYTES], const uint8_t* response)
{
    // Check: linear_map(response) == commitment + image * challenge
    size_t num_constraints = relation->map.num_constraints;

    // Compute expected = linear_map(response)
    uint8_t* expected = malloc(num_constraints * POINT_BYTES);
    if (linear_map_eval(&relation->map, response, expected) != 0) {
        free(expected);
        return false;
    }

    // Compute got[i] = commitment[i] + image[i] * challenge
    for (size_t i = 0; i < num_constraints; i++) {
        const uint8_t* image_i      = &relation->image[i * POINT_BYTES];
        const uint8_t* commitment_i = &commitment[i * POINT_BYTES];
        uint8_t*       expected_i   = &expected[i * POINT_BYTES];

        // c_times_image = challenge * image[i]
        uint8_t c_times_image[POINT_BYTES];
        if (crypto_scalarmult_ristretto255(c_times_image, challenge, image_i) != 0) {
            free(expected);
            return false;
        }

        // got = commitment[i] + c_times_image
        uint8_t got[POINT_BYTES];
        if (crypto_core_ristretto255_add(got, commitment_i, c_times_image) != 0) {
            free(expected);
            return false;
        }

        // Check expected[i] == got
        if (sodium_memcmp(expected_i, got, POINT_BYTES) != 0) {
            free(expected);
            return false;
        }
    }

    free(expected);
    return true;
}

// ============================================================================
// Zero-Knowledge Simulator (Optional)
// ============================================================================

// Simulate random response (spec section 1.1)
void
simulate_response(size_t num_scalars, uint8_t* response)
{
    for (size_t i = 0; i < num_scalars; i++) {
        crypto_core_ristretto255_scalar_random(&response[i * SCALAR_BYTES]);
    }
}

// Simulate commitment given response and challenge (spec section 1.1)
// commitment = linear_map(response) - image * challenge
int
simulate_commitment(const linear_relation_t* relation, const uint8_t* response,
                    const uint8_t challenge[SCALAR_BYTES], uint8_t* commitment)
{
    size_t num_constraints = relation->map.num_constraints;

    // Compute linear_map(response)
    uint8_t* map_response = malloc(num_constraints * POINT_BYTES);
    if (linear_map_eval(&relation->map, response, map_response) != 0) {
        free(map_response);
        return -1;
    }

    // commitment[i] = map_response[i] - image[i] * challenge
    for (size_t i = 0; i < num_constraints; i++) {
        const uint8_t* image_i        = &relation->image[i * POINT_BYTES];
        const uint8_t* map_response_i = &map_response[i * POINT_BYTES];
        uint8_t*       commitment_i   = &commitment[i * POINT_BYTES];

        // c_times_image = challenge * image[i]
        uint8_t c_times_image[POINT_BYTES];
        if (crypto_scalarmult_ristretto255(c_times_image, challenge, image_i) != 0) {
            free(map_response);
            return -1;
        }

        // commitment[i] = map_response[i] - c_times_image
        // Use subtraction: a - b = a + (-b)
        if (crypto_core_ristretto255_sub(commitment_i, map_response_i, c_times_image) != 0) {
            free(map_response);
            return -1;
        }
    }

    free(map_response);
    return 0;
}
