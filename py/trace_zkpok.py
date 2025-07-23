#!/usr/bin/env python3

from py_ecc.bls12_381 import *
from TTP import *
import random

def trace_zkpok():
    """Trace every step of ZKPoK carefully"""
    print("=== Tracing ZKPoK step by step ===")
    
    # Setup
    params = ttp_setup(2, "test_ttp")
    _, g, o, hs = params
    h = hs[0]  # Use first hash generator
    
    # Original attribute and randomness
    attr_msk = 1000
    attr_value = 42
    randomness = 100
    
    print(f"Attribute: {attr_value}")
    print(f"Randomness: {randomness}")
    
    # Commitment: C = g^randomness * h^attribute
    commitment = add(multiply(g, randomness), multiply(h, attr_value))
    print(f"Commitment: {commitment}")
    
    # Witness values
    w_attr = 55
    w_rand = 77
    
    print(f"Witness for attribute: {w_attr}")
    print(f"Witness for randomness: {w_rand}")
    
    # Witness commitment: W = g^w_rand * h^w_attr
    witness = add(multiply(g, w_rand), multiply(h, w_attr))
    print(f"Witness commitment: {witness}")
    
    # Challenge from hash
    element_list = [g, witness, commitment, h]
    challenge = toChallenge(element_list) % o
    print(f"Challenge: {challenge}")
    
    # Responses
    resp_attr = (w_attr - challenge * attr_value) % o
    resp_rand = (w_rand - challenge * randomness) % o
    
    print(f"Response for attribute: {resp_attr}")
    print(f"Response for randomness: {resp_rand}")
    
    # Verification: g^resp_rand * h^resp_attr * C^challenge = W
    verify_point = add(add(multiply(g, resp_rand), multiply(h, resp_attr)), multiply(commitment, challenge))
    print(f"Verification point: {verify_point}")
    print(f"Original witness: {witness}")
    print(f"Verification successful: {verify_point == witness}")
    
    # Manual algebra check
    print(f"\n=== Algebra Check ===")
    print(f"resp_attr + challenge * attr_value = {resp_attr} + {challenge} * {attr_value} = {(resp_attr + challenge * attr_value) % o}")
    print(f"Should equal w_attr = {w_attr}")
    print(f"Attribute algebra correct: {(resp_attr + challenge * attr_value) % o == w_attr}")
    
    print(f"resp_rand + challenge * randomness = {resp_rand} + {challenge} * {randomness} = {(resp_rand + challenge * randomness) % o}")  
    print(f"Should equal w_rand = {w_rand}")
    print(f"Randomness algebra correct: {(resp_rand + challenge * randomness) % o == w_rand}")
    
    # Now test with the actual functions
    print(f"\n=== Testing with TTP functions ===")
    
    # Create encoded attributes (attribute + randomness)
    encoded_attr = [attr_msk, attr_value, randomness]
    all_enc_attr = [encoded_attr]
    
    # Generate commitment using function
    func_commitment = GenCommitment(params, encoded_attr)
    print(f"Function commitment: {func_commitment}")
    print(f"Manual vs function commitment match: {commitment == func_commitment}")
    
    # Generate proof using function  
    prev_params = []
    prev_vcerts = []
    
    # Set fixed randomness for reproducibility
    random.seed(42)
    proof = GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, func_commitment)
    func_challenge, func_responses = proof
    
    print(f"Function challenge: {func_challenge}")
    print(f"Function responses: {func_responses[0]}")
    
    # Verify using function (pass only the attribute, not randomness)
    verify_result = VerifyZKPoK(params, prev_params, prev_vcerts, [attr_value], func_commitment, proof)
    print(f"Function verification result: {verify_result}")

if __name__ == "__main__":
    trace_zkpok()
