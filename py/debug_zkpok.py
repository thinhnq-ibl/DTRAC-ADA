#!/usr/bin/env python3

from py_ecc.bn128 import *
from TTP import *
import random

def debug_zkpok():
    print("Debugging Zero-Knowledge Proof functions...")
    
    # Setup parameters
    params = ttp_setup(2, "test_ttp")
    _, g, o, hs = params
    
    # Create some test attributes with just one for simplicity
    attr = [100, "Alice"]
    encode_str = [2,1]  # Hash the attribute
    encoded_attr = encode_attributes(attr, encode_str)
    
    # Add randomness parameter for the commitment
    randomness = random.randint(1, o - 1)
    encoded_attr.append(randomness)
    
    print(f"Encoded attributes: {encoded_attr}")
    print(f"Number of hash generators: {len(hs)}")
    
    # Generate commitment using function
    comm = GenCommitment(params, encoded_attr)
    print(f"Commitment: {comm}")
    
    # Test ZKPoK with empty previous certificates
    prev_params = []
    prev_vcerts = []
    all_enc_attr = [encoded_attr]
    
    # Set a fixed seed for reproducible testing
    random.seed(12345)
    
    # Generate proof using function
    proof = GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, comm)
    c, total_rm = proof
    print(f"Function challenge: {c}")
    print(f"Response: {total_rm[0]}")
    
    # Reset seed and manually recreate the same proof
    random.seed(12345)
    
    print("\n--- Manual GenZKPoK ---")
    # Manual proof generation using same random values
    total_wm = [[random.randint(2, o) for _ in range(len(all_enc_attr[i]))] for i in range(len(all_enc_attr))]
    print(f"Witness: {total_wm[0]}")
    
    # Generate witness commitment manually
    witness_comm = multiply(g, total_wm[0][-1])  # randomness term
    witness_comm = add(witness_comm, multiply(hs[0], total_wm[0][0]))  # attribute term
    
    print(f"Manual witness commitment: {witness_comm}")
    
    # Create element list as in GenZKPoK
    Aw = [witness_comm]
    comm_list = [comm]
    element_list = [g] + Aw + comm_list + hs
    
    c_manual = toChallenge(element_list) % o
    print(f"Manual challenge: {c_manual}")
    print(f"Function and manual challenges match: {c == c_manual}")
    
    # Manual response computation
    rm_manual = [(total_wm[0][j] - c*all_enc_attr[0][j]) % o for j in range(len(total_wm[0]))]
    print(f"Manual response: {rm_manual}")
    print(f"Function and manual responses match: {total_rm[0] == rm_manual}")
    
    print("\n--- Manual VerifyZKPoK ---")
    tmp_comm = multiply(hs[1], encoded_attr[1])


	# for i in range(2, len(hs)):
	# 	tmp_comm = add(tmp_comm, multiply(hs[i], encoded_attr[i-1]))
    tmp_comm = add(comm, neg(tmp_comm))
    # Manual verification
    verify_witness = multiply(g, total_rm[0][-1])  # randomness response
    verify_witness = add(verify_witness, multiply(hs[0], total_rm[0][0]))  # attribute response
    verify_witness = add(verify_witness, multiply(tmp_comm, c))  # challenge * commitment
    
    print(f"Verify witness: {verify_witness}")
    
 

    # Create verification element list
    verify_Aw = [verify_witness]
    verify_comm_list = [comm]
    verify_element_list = [g] + verify_Aw + verify_comm_list + hs
    
    c_verify = toChallenge(verify_element_list) % o
    print(f"Verify challenge: {c_verify}")
    print(f"Original challenge: {c}")
    print(f"Verification challenges match: {c == c_verify}")
    
    # Verify proof using function - pass only the attributes WITHOUT randomness
    original_attr = encoded_attr[1:len(encoded_attr)-1]  # Remove the randomness we added
    print("original_attr", original_attr)
    result = VerifyZKPoK(params, prev_params, prev_vcerts, original_attr, comm, proof)
    print(f"Function verification result: {result}")

if __name__ == "__main__":
    debug_zkpok()
