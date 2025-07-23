#!/usr/bin/env python3

from py_ecc.bls12_381 import *
from TTP import *
import random

def test_with_ttp_generators():
    """Test ZKPoK using the exact same approach as TTP functions"""
    print("=== Testing with TTP hash generators ===")
    
    # Use TTP setup
    params = ttp_setup(2, "test_ttp")
    _, g, o, hs = params
    h = hs[0]  # First hash generator from TTP
    
    print(f"Generator g: {g}")
    print(f"Hash generator h: {h}")
    
    # Use simple values
    attr_msk = 1000
    attr_value = 42
    randomness = 100
    
    # Create encoded attributes as TTP expects
    encoded_attr = [attr_msk, attr_value, randomness]
    
    # Generate commitment using TTP function
    commitment = GenCommitment(params, encoded_attr)
    print(f"TTP Commitment: {commitment}")
    
    # Manual commitment to verify
    manual_commitment = add(multiply(g, randomness), multiply(h, attr_value))
    print(f"Manual commitment: {manual_commitment}")
    print(f"Commitments match: {commitment == manual_commitment}")
    
    # Generate ZKPoK proof
    prev_params = []
    prev_vcerts = []
    all_enc_attr = [encoded_attr]
    
    # Use fixed seed for reproducibility
    random.seed(12345)
    proof = GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, commitment)
    challenge, responses = proof
    
    print(f"Challenge: {challenge}")
    print(f"Responses: {responses[0]}")
    
    # Verify using TTP function
    # Note: Pass only the attribute (without randomness) to verify
    verify_result = VerifyZKPoK(params, prev_params, prev_vcerts, [attr_value], commitment, proof)
    print(f"TTP Verification result: {verify_result}")
    
    # Manual verification to double-check
    resp_attr = responses[0][0]  # First response (attribute)
    resp_rand = responses[0][1]  # Second response (randomness)
    
    print(f"Response for attribute: {resp_attr}")
    print(f"Response for randomness: {resp_rand}")
    
    # Manual verification: g^resp_rand * h^resp_attr * commitment^challenge
    manual_verify = add(add(multiply(g, resp_rand), multiply(h, resp_attr)), multiply(commitment, challenge))
    
    # To check if this is correct, we need to know what the original witness was
    # Let's generate the same witness manually
    random.seed(12345)
    w_attr = random.randint(2, o)
    w_rand = random.randint(2, o)
    
    manual_witness = add(multiply(g, w_rand), multiply(h, w_attr))
    print(f"Manual witness: {manual_witness}")
    print(f"Manual verification point: {manual_verify}")
    print(f"Manual verification matches: {manual_verify == manual_witness}")
    
    return verify_result

if __name__ == "__main__":
    success = test_with_ttp_generators()
    if success:
        print("\n✅ TTP ZKPoK verification successful!")
    else:
        print("\n❌ TTP ZKPoK verification failed!")
