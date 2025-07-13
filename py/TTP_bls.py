from py_ecc.bls12_381 import * 
from hashlib import sha256
import random
import time
from py_ecc.bls.point_compression import (
    compress_G1,
    decompress_G1,
    compress_G2,
    decompress_G2,
    G1Uncompressed
)
from py_ecc.fields import (
    optimized_bls12_381_FQ as FQO,
    optimized_bls12_381_FQ2 as FQO2,
    optimized_bls12_381_FQ12 as FQO12,
    optimized_bls12_381_FQP as FQPO,
)

from py_ecc.bls.hash import (
    i2osp,
    os2ip
)

def genRandom():
	o = int(curve_order)
	return random.randint(2, o)

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 4) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    h = sha256(byte_string).digest()
    x = int.from_bytes(h, 'big') % curve_order
    return multiply(G1, x)

def ttp_setup(q, ttp):
	assert q > 0
	hs = [hashG1((ttp+("h%s")% i).encode("utf8")) for i in range(q)]
	return ((FQ, FQ2, FQ12), G1, int(curve_order), hs)

def ttpKeyGen(params):
	_, g, o, hs = params
	sk = random.randint(2, o)
	pk = multiply(g, sk)
	return pk, sk

def encode_attributes(attr, encode_str):
	o = int(curve_order)
	encoded_attr = []
	assert len(attr) == len(encode_str), "mismatch in encoding lengths"
	for i in range(len(attr)):
		if encode_str[i] == 1:
			Chash = sha256(attr[i].encode("utf8").strip()).digest()
			encoded_attr.append(int.from_bytes(Chash, "big") % o)
		else:
			encoded_attr.append(attr[i])
	return encoded_attr

def GenCommitment(params, encoded_attr):
	_, g, o, hs = params 
	Aw = [multiply(hs[i], encoded_attr[i]) for i in range(len(hs))]
	comm = multiply(g, encoded_attr[len(hs)])
	for i in range(0, len(Aw)):
		comm = add(comm, Aw[i])
	return comm

def toChallenge(element_list):
	"""Packages a challenge in a bijective way"""
	Cstring = SHA256(element_list[0])
	for i in range(1, len(element_list)):
		Cstring += SHA256(element_list[i])
	Chash = sha256(Cstring).digest()
	return (int.from_bytes(Chash, "big"))

def SHA256(element):
    # return sha256((element[0].n).to_bytes(48, 'big') + (element[1].n).to_bytes(48, 'big')).digest()
    g1_point: G1Uncompressed = (FQO(element[0].n),FQO(element[1].n), FQO(1))
    return sha256(i2osp(compress_G1(g1_point),48)).digest()
def get_g1_bytes(point):
    commitUncompress = (FQO(point[0].n), FQO(point[1].n), FQO(1))
    return i2osp(compress_G1(commitUncompress),48).hex()

def get_g2_bytes(point):
    commit2Uncompress = (FQO2([point[0].coeffs[0].n, point[0].coeffs[1].n]), FQO2([point[1].coeffs[0].n, point[1].coeffs[1].n]), FQO2.one())
    commit2Compress = compress_G2(commit2Uncompress)
    return i2osp(commit2Compress[0], 48).hex() + i2osp(commit2Compress[1], 48).hex()

def get_list_g1_bytes(points):
    ret = []
    for point in points:
        commitUncompress = (FQO(point[0].n), FQO(point[1].n), FQO(1))
        ret.append(i2osp(compress_G1(commitUncompress),48).hex())
    return ret

def get_list_g2_bytes(points):
    ret = []
    for point in points:
        commit2Uncompress = (FQO2([point[0].coeffs[0].n, point[0].coeffs[1].n]), FQO2([point[1].coeffs[0].n, point[1].coeffs[1].n]), FQO2.one())
        commit2Compress = compress_G2(commit2Uncompress)
        ret.append(i2osp(commit2Compress[0], 48).hex() + i2osp(commit2Compress[1], 48).hex())
    return ret
	
def GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, comm):
	_, g, o, hs= params
	total_wm = [[random.randint(2, o) for _ in range(len(all_enc_attr[i]))] for i in range(len(all_enc_attr))]
	for i in range(1, len(total_wm)):
		total_wm[i][0] = total_wm[0][0]
	Aw = []
	comm_list = []
	for i in range(len(prev_vcerts)):
		(_, ttp_g, _, ttp_hs) = prev_params[i]
		tmp = multiply(ttp_g, total_wm[i][-1])
		for j in range(len(total_wm[i]) - 1):
			tmp = add(tmp, multiply(ttp_hs[j], total_wm[i][j]))
		Aw.append(tmp)
		comm_list.append(prev_vcerts[i][0])

	_tmp = multiply(g, total_wm[len(prev_vcerts)][-1])
	_tmp = add(_tmp, multiply(hs[0], total_wm[len(prev_vcerts)][0]))
	Aw.append(_tmp)
	comm_list.append(comm)

	element_list = [g] + Aw + comm_list + hs 
	c = toChallenge(element_list) % o
	total_rm = [[(total_wm[i][j] - c*all_enc_attr[i][j]) % o for j in range(len(total_wm[i]))] for i in range(len(total_wm))]
	return (c, total_rm)

def VerifyZKPoK(params, prev_params, prev_vcerts, encoded_attr, comm, ZKPoK):
	c, total_rm = ZKPoK
	for i in range(1, len(total_rm)):
		if total_rm[0][0] != total_rm[i][0]:
			return False

	_, g, o, hs= params

	# tmp_comm = multiply(hs[1], encoded_attr[0])

	# for i in range(2, len(hs)):
	# 	tmp_comm = add(tmp_comm, multiply(hs[i], encoded_attr[i-1]))
	# tmp_comm = add(comm, neg(tmp_comm))

	# comm_list = []
	# Aw = []
	# for i in range(len(prev_vcerts)):
	# 	(_, ttp_g, _, ttp_hs) = prev_params[i]
	# 	tmp = multiply(ttp_g, total_rm[i][-1])
	# 	for j in range(len(total_rm[i]) - 1):
	# 		tmp = add(tmp, multiply(ttp_hs[j], total_rm[i][j]))
	# 	tmp = add(tmp, multiply(prev_vcerts[i][0], c))
	# 	Aw.append(tmp)
	# 	comm_list.append(prev_vcerts[i][0])

	# _, g, o, hs= params
	# _tmp = multiply(g, total_rm[len(prev_vcerts)][-1])
	# _tmp = add(_tmp, multiply(hs[0], total_rm[len(prev_vcerts)][0]))
	# _tmp = add(_tmp, multiply(tmp_comm,c))
	# Aw.append(_tmp)
	# comm_list.append(comm)

	# element_list = [g]+ Aw + comm_list + hs
	# return (c == toChallenge(element_list) % o)
	return True

def SignCommitment(params, sk, comm):
	G, g, o, hs= params
	digest = SHA256(comm)
	sign = do_ecdsa_sign(sk, digest)
	return sign

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
 
    if (m == 1):
        return 0
 
    while (a > 1):
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0):
        x = x + m0
 
    return x

def VerifyVcerts(params, pk, sign, digest):
	return do_ecdsa_verify(pk, sign, digest)

def get_int_digest(params, comm):
    G, g, o, hs = params
    digest = SHA256(comm)
    int_digest = int.from_bytes(digest, "big") % o
    return int_digest

def do_ecdsa_sign(sk, digest):
    r = 0
    s = 0
    o = int(curve_order)
    int_digest = int.from_bytes(digest, "big") % o
    while r == 0 or s==0 :
        k = random.randint(2, o)
        p1 = multiply(G1, k)
        r = p1[0].n
        r_g1 = i2osp(compress_G1((FQO(p1[0].n),
                              FQO(p1[1].n), 
                              FQO(1))),48).hex()
        s = (modInverse(k, o) * (int_digest + ((sk * r) % o)) ) %o
    return (r, s, r_g1)

def do_ecdsa_verify(pk, sign, digest):
	(r, s, r_g1) = sign
	o = int(curve_order)
	int_digest = int.from_bytes(digest, "big") % o
	s1 = modInverse(s, o)
	x1 = (int_digest * s1) % o
	x2 = (r * s1) % o
	pt1 = multiply(G1, x1)
	pt2 = multiply(pk, x2)
	_r = add(pt1, pt2)
	return r == _r[0].n