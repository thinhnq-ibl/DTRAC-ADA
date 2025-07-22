#!/usr/bin/env python3

from py_ecc.bls12_381 import *
from TTP import *
import random

def test_basic_functions():
    print("Testing BLS12-381 curve functions...")
    
    # Test curve parameters
    print(f"Field modulus: {field_modulus}")
    print(f"Curve order: {curve_order}")
    print(f"Generator G1: {G1}")
    
    # Test FindYforX
    x = random.randint(1, field_modulus - 1)
    beta, y = FindYforX(x)
    print(f"FindYforX test: x={x}, beta={beta}, y={y}")
    
    # Test hashG1
    test_string = b"test_hash_to_g1"
    h = hashG1(test_string)
    print(f"hashG1 test: {h}")
    
    # Test TTP setup
    params = ttp_setup(3, "test_ttp")
    print(f"TTP setup test: {len(params)} parameters")
    
    return params

def test_zkpok():
    print("\nTesting Zero-Knowledge Proof functions...")
    
    # Setup parameters
    params = ttp_setup(5, "test_ttp")
    _, g, o, hs = params
    
    # Create some test attributes
    attr = ["Alice", "25", "Engineer", "100000"]
    encode_str = [1, 0, 1, 0]  # Hash first and third attributes
    encoded_attr = encode_attributes(attr, encode_str)
    
    # Add randomness parameter for the commitment
    randomness = random.randint(1, o - 1)
    encoded_attr.append(randomness)
    
    print(f"Encoded attributes: {encoded_attr}")
    print(f"Number of hash generators: {len(hs)}")
    print(f"Number of attributes (including randomness): {len(encoded_attr)}")
    
    # Generate commitment
    comm = GenCommitment(params, encoded_attr)
    print(f"Commitment: {comm}")
    
    # Test ZKPoK with empty previous certificates (simple case)
    prev_params = []
    prev_vcerts = []
    all_enc_attr = [encoded_attr]
    
    # Generate proof
    try:
        proof = GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, comm)
        print(f"Generated ZKPoK proof: challenge length = {len(str(proof[0]))}")
        
        # Verify proof
        result = VerifyZKPoK(params, prev_params, prev_vcerts, encoded_attr, comm, proof)
        print(f"ZKPoK verification result: {result}")
        
        return result
    except Exception as e:
        print(f"Error in ZKPoK: {e}")
        return False

if __name__ == "__main__":
    try:
        params = test_basic_functions()
        success = test_zkpok()
        
        if success:
            print("\n✅ All tests passed! BLS12-381 integration is working correctly.")
        else:
            print("\n❌ Some tests failed. Check the implementation.")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
