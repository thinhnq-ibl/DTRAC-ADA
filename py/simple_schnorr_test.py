#!/usr/bin/env python3

from py_ecc.bls12_381 import *
from TTP import toChallenge
import random

def simple_schnorr_test():
    """Test basic Schnorr proof with BLS12-381"""
    print("Testing simple Schnorr proof...")
    
    g = G1
    o = curve_order
    
    # Secret
    x = 12345
    
    # Commitment 
    commitment = multiply(g, x)
    print(f"Commitment: {commitment}")
    
    # Witness (random)
    r = 67890
    witness = multiply(g, r)
    print(f"Witness: {witness}")
    
    # Challenge
    element_list = [g, commitment, witness]
    c = toChallenge(element_list) % o
    print(f"Challenge: {c}")
    
    # Response
    z = (r - c * x) % o
    print(f"Response: {z}")
    
    # Verification: g^z * commitment^c should equal witness
    verification = add(multiply(g, z), multiply(commitment, c))
    print(f"Verification point: {verification}")
    print(f"Original witness: {witness}")
    print(f"Verification successful: {verification == witness}")
    
    # Double-check the algebra manually
    print(f"\nAlgebra check:")
    print(f"z + c*x = {z} + {c}*{x} = {(z + c*x) % o}")
    print(f"Should equal r = {r}")
    print(f"Algebra correct: {(z + c*x) % o == r}")
    
    return verification == witness

if __name__ == "__main__":
    success = simple_schnorr_test()
    if success:
        print("\n✅ Basic Schnorr proof works!")
    else:
        print("\n❌ Basic Schnorr proof failed!")
