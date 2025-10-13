#ifndef LINEAR_RELATION_H
#define LINEAR_RELATION_H

#include "csigma.h"

// General framework for Sigma protocols over Ristretto255
// Implements the LinearRelation abstraction from draft-irtf-cfrg-sigma-protocols-00

// Linear combination: represents sum of (scalar_i * element_i) terms
// This is one row in the linear map matrix (in sparse format)
typedef struct {
    int*   scalar_indices; // Indices into the scalar array
    int*   element_indices; // Indices into the group element array
    size_t num_terms; // Number of terms in this linear combination
    size_t capacity; // Allocated capacity
} linear_combination_t;

// Linear map: function from scalars to group elements
// Represents matrix multiplication in sparse format
typedef struct {
    linear_combination_t* combinations; // Array of linear combinations (rows)
    uint8_t*              group_elements; // Array of group elements (32 bytes each)
    size_t                num_constraints; // Number of equations (rows)
    size_t                num_scalars; // Number of scalar variables
    size_t                num_elements; // Number of group elements
    size_t                constraints_capacity; // Allocated capacity for constraints
    size_t                elements_capacity; // Allocated capacity for elements
} linear_map_t;

// Linear relation: statement proving knowledge of preimage
// Proves: "I know witness such that linear_map(witness) = image"
typedef struct {
    linear_map_t map;
    uint8_t*     image; // Expected output (num_constraints points)
} linear_relation_t;

// Prover state for interactive/non-interactive protocols
typedef struct {
    uint8_t* witness; // Secret scalars
    uint8_t* nonces; // Random nonces used in commitment
    size_t   num_scalars;
} prover_state_t;

// Linear combination operations (internal, for advanced use)
void linear_combination_init(linear_combination_t* lc);
void linear_combination_add_term(linear_combination_t* lc, int scalar_idx, int element_idx);
void linear_combination_destroy(linear_combination_t* lc);

// Linear map operations (internal, for advanced use)
void linear_map_init(linear_map_t* map);
void linear_map_destroy(linear_map_t* map);

// Evaluate: map(scalars) -> group elements
// scalars: array of num_scalars 32-byte scalars
// output: array of num_constraints 32-byte group elements (must be pre-allocated)
int linear_map_eval(const linear_map_t* map, const uint8_t* scalars, uint8_t* output);

// Linear relation builder API (following spec section 2.2.6)
void csigma_relation_init(linear_relation_t* relation);
void csigma_relation_destroy(linear_relation_t* relation);

// Allocate scalar variables (returns base index)
// Use this for witness scalars (values set during proving)
int csigma_relation_allocate_scalars(linear_relation_t* relation, size_t n);

// Allocate group element variables (returns base index)
// After allocation, set values with csigma_relation_set_element()
int csigma_relation_allocate_elements(linear_relation_t* relation, size_t n);

// Set group element value (after allocation)
// element: 32-byte point in Ristretto255
void csigma_relation_set_element(linear_relation_t* relation, int index,
                                 const uint8_t element[CSIGMA_POINT_BYTES]);

// SIMPLIFIED API: Add element and get its index in one call
// This combines allocate_elements(1) + set_element()
// Returns the element's index
int csigma_relation_add_element(linear_relation_t* relation,
                                const uint8_t      element[CSIGMA_POINT_BYTES]);

// SIMPLIFIED API: Add scalar variable
// This is just allocate_scalars(1) with a clearer name
// Returns the scalar's index
int csigma_relation_add_scalar(linear_relation_t* relation);

// Append equation: lhs = sum of (scalar[rhs[i].scalar_idx] * element[rhs[i].element_idx])
// lhs: index of image element
// rhs_scalar_indices: array of scalar variable indices
// rhs_element_indices: array of group element indices
// num_terms: number of terms in the sum
void csigma_relation_add_equation(linear_relation_t* relation, int lhs,
                                  const int* rhs_scalar_indices, const int* rhs_element_indices,
                                  size_t num_terms);

// SIMPLIFIED API: Add equation with single term (most common case)
// Equation: element[lhs_idx] = scalar[scalar_idx] * element[element_idx]
// Example: Y = x*G means csigma_relation_add_equation_simple(&rel, Y_idx, x_idx, G_idx)
void csigma_relation_add_equation_simple(linear_relation_t* relation, int lhs_idx, int scalar_idx,
                                         int element_idx);

// General sigma protocol interface (spec section 1.1)

// Prover commit: generate commitment and prover state
// witness: array of num_scalars 32-byte scalars
// commitment: output array (num_constraints 32-byte points, pre-allocated)
// state: output prover state (must be freed with csigma_prover_state_destroy)
// Returns 0 on success, -1 on error
int csigma_prover_commit(const linear_relation_t* relation, const uint8_t* witness,
                         uint8_t* commitment, prover_state_t* state);

// Prover response: compute response given challenge
// state: prover state from commit phase
// challenge: 32-byte challenge scalar
// response: output array (num_scalars 32-byte scalars, pre-allocated)
void csigma_prover_response(const prover_state_t* state,
                            const uint8_t challenge[CSIGMA_SCALAR_BYTES], uint8_t* response);

// Verifier: check proof transcript
// relation: the statement being proven
// commitment: commitment from prover (num_constraints points)
// challenge: challenge scalar
// response: response from prover (num_scalars scalars)
// Returns true if proof is valid, false otherwise
bool csigma_verify(const linear_relation_t* relation, const uint8_t* commitment,
                   const uint8_t challenge[CSIGMA_SCALAR_BYTES], const uint8_t* response);

// Prover state management
void csigma_prover_state_init(prover_state_t* state, size_t num_scalars);
void csigma_prover_state_destroy(prover_state_t* state);

#endif
