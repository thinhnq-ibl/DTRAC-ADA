from TTP import *
from py_ecc_tester import *
import datetime
from py_ecc.bls.hash import (
    i2osp,
    os2ip
)
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

##################################
## create vcert
##################################

# Identity Certificate

# Set a fixed seed for reproducible testing
random.seed(12345)
msk = genRandom()
user_addr = "0x1A1684c3027eA12046155013BfC5518C65dD5943"

schema = {}
encoding = {}
schemaOrder = []

encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

key = "msk"
schemaOrder.append(key)
schema.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding.setdefault(key, 2)

key = "name"
schemaOrder.append(key)
schema.setdefault(key, {"type" : encoding_type_map["1"], "visibility": "private"})
encoding.setdefault(key, 1)

key = "dob"
schemaOrder.append(key)
schema.setdefault(key, {"type" : encoding_type_map["3"], "visibility": "private"})
encoding.setdefault(key, 3)

key = "r"
schemaOrder.append(key)
schema.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding.setdefault(key, 2)

q = len(schemaOrder)

args = {}
args.setdefault("title", "Identity Certificate" )

params = ttp_setup(q-1, args["title"]) # exclude r.
pk, sk = ttpKeyGen(params)

r = genRandom()
_date = datetime.datetime.strptime("1998-05-12","%Y-%m-%d").date()
value_date = int(_date.strftime('%Y%m%d'))
attribute = [msk, "Justin", value_date, r]
encode_str = [2,1,2,2]

encoded_attribute = encode_attributes(attribute, encode_str)
commit = GenCommitment(params, encoded_attribute)

prevAttributes = []
prevAttributes.append([attribute[0], attribute[-1]])

prevParams = []
prevVcerts = []
zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)
new_attribute = ["Justin", value_date]
new_encode_str = [1,2]
new_encoded_attribute = encode_attributes(new_attribute, new_encode_str)
verify_zkp = VerifyZKPoK(params, prevParams, prevVcerts, new_encoded_attribute, commit, zkpok)
print ("verify_zkp", verify_zkp)
signature = SignCommitment(params, sk, commit)

vcert = {}
vcert["attributes"] = encoded_attribute
vcert["commit"] = commit
vcert["signature"] = signature

# Income Certificate
msk2 = genRandom()
schema2 = {}
encoding2 = {}
schemaOrder2 = []

key = "msk"
schemaOrder2.append(key)
schema2.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding2.setdefault(key, 2)

key = "salary"
schemaOrder2.append(key)
schema2.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding2.setdefault(key, 2)

key = "r"
schemaOrder2.append(key)
schema2.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding2.setdefault(key, 2)

q2 = len(schemaOrder2)

args2 = {}
args2.setdefault("title", "Income Certificate" )

params2 = ttp_setup(q2-1, args2["title"]) # exclude r.
pk2, sk2 = ttpKeyGen(params2)

r2 = genRandom()
attribute2 = [msk, 10000, r2]
encode_str2 = [2,2,2]

encoded_attribute2 = encode_attributes(attribute2, encode_str2)
commit2 = GenCommitment(params2, encoded_attribute2)

prevAttributes2 = [encoded_attribute]
prevAttributes2.append([encoded_attribute2[0], encoded_attribute2[-1]])

prevParams2 = [params]
prevVcerts2 = [(commit, signature)]
zkpok2 = GenZKPoK(params2, prevParams2, prevVcerts2, prevAttributes2, commit2)
verify_zkp2 = VerifyZKPoK(params2, prevParams2, prevVcerts2, [10000], commit2, zkpok2)
print ("verify_zkp2", verify_zkp2)
signature2 = SignCommitment(params2, sk2, commit2)

vcert2 = {}
vcert2["attributes"] = encoded_attribute2
vcert2["commit"] = commit2
vcert2["signature"] = signature2
######################################
## create credential
######################################

ac_title = "Loan Credential"
attributes = {'DOB': 19980512, 'Salary': 10000}
credential = {"title": ac_title, "attributes" : attributes, "credential": None}
q = 2
validator_params = setup(q, ac_title)
(_, _, _, hs, _, _) = validator_params
nv = 3 #getTotalValidators(args.title)
tv = 2 #getThresholdValidators(args.title)
#q = getTotalAttributes(args.title)
(sk, vk) = ttp_keygen(validator_params, tv, nv)
# #print("sk, vk", sk, vk)
aggregate_vk = agg_key(validator_params, vk)
to = 2 #getThresholdOpeners(args.title) 
no = 3 #getTotalOpeners(args.title)
(opk, osk) = opener_keygen( validator_params)
(opk1, osk1) = opener_keygen(validator_params)
(opk2, osk2) = opener_keygen(validator_params)
opks = [opk, opk1, opk2]

combination = ["Identity Certificate", "Income Certificate"]
vcerts = [vcert, vcert2]

prevVcerts = [(vcert["commit"], vcert["signature"]), (vcert2["commit"], vcert2["signature"])]	
prevParams = [params, params2]
all_encoded_attr = [encoded_attribute, encoded_attribute2]

include_indexes = [[0, 0, 1, 0], [0, 1, 0]]
Lambda, os = PrepareCredRequest(validator_params, aggregate_vk, to, no, opks, prevParams, all_encoded_attr, include_indexes, public_m=[])

(cm, commitments, pi_s, hp, C, pi_o, Dw, Ew, hr, bo) = Lambda
#anything with "send" appended is making that particular variable as SC compatible.
send_cm = (cm[0].n, cm[1].n)
send_commitments = [(commitments[i][0].n, commitments[i][1].n) for i in range(len(commitments))]
send_ciphershares= [([([C[i][j][0].coeffs[1].n,C[i][j][0].coeffs[0].n],[C[i][j][1].coeffs[1].n, C[i][j][1].coeffs[0].n]) for j in range(2)],) for i in range(len(C))]
send_compressed_cipher = (send_commitments, send_ciphershares)
private_m = [19980512, 100000]
# schema = downloadSchema(title)
# schemaOrder = downloadSchemaOrder(title)
# for key in schemaOrder:
#     if schema[key]['visibility'] == 'private':
#         private_m.append(credential["attributes"][key])

send_hp =  [[(hp[i][j-1][0].n, hp[i][j-1][1].n) for j in range(1, to)] for i in range(len(private_m))]
send_hr = [(hr[i][0].n, hr[i][1].n) for i in range(len(hr))]
send_bo = [([bo[i][0].coeffs[1].n,bo[i][0].coeffs[0].n],[bo[i][1].coeffs[1].n,bo[i][1].coeffs[0].n]) for i in range(len(bo))]
send_Dw = [([Dw[i][0].coeffs[1].n,Dw[i][0].coeffs[0].n],[Dw[i][1].coeffs[1].n,Dw[i][1].coeffs[0].n]) for i in range(len(Dw))]
send_Ew = [([Ew[i][0].coeffs[1].n,Ew[i][0].coeffs[0].n],[Ew[i][1].coeffs[1].n,Ew[i][1].coeffs[0].n]) for i in range(len(Ew))]
send_compressed_G2Points = (send_Dw, send_Ew)
send_vcerts = [((prevVcerts[i][0][0].n, prevVcerts[i][0][1].n), prevVcerts[i][1]) for i in range(len(prevVcerts))]

pi_s_old = pi_s

pi_s = list(pi_s)
pi_s.append(combination)
pi_s = tuple(pi_s)

print("pi_s", pi_s)
# validator 1
Lambda2 = (cm, commitments)
# #print("sk", sk)
blind_sig = BlindSignAttr(validator_params, sk[0], Lambda2, [])

send_h = [blind_sig[0][0].n, blind_sig[0][1].n]
send_t = [blind_sig[1][0].n, blind_sig[1][1].n]

print("send_h_compress: ", i2osp(compress_G1((send_h[0], send_h[1], FQO(1))),96).hex())
# #print("send_t: ", send_t)

h = (FQ(send_h[0]), FQ(send_h[1]))
t = (FQ(send_t[0]), FQ(send_t[1]))

blind_sig = (h, t)
sigma = Unblind(validator_params, aggregate_vk, blind_sig, os)
# #print("sigma: ", sigma)

# validator 2
# Lambda2 = (cm, commitments)
# #print("sk", sk)
blind_sig2 = BlindSignAttr(validator_params, sk[1], Lambda2, [])

send_h2 = [blind_sig2[0][0].n, blind_sig2[0][1].n]
send_t2 = [blind_sig2[1][0].n, blind_sig2[1][1].n]

# #print("send_h: ", send_h2)
# #print("send_t: ", send_t2)

h2 = (FQ(send_h2[0]), FQ(send_h2[1]))
t2 = (FQ(send_t2[0]), FQ(send_t2[1]))

blind_sig2 = (h2, t2)
sigma2 = Unblind(validator_params, aggregate_vk, blind_sig2, os)
# #print("sigma: ", sigma)

signs = []
signs.append(sigma)
signs.append(sigma2)

aggr_sig = AggCred(validator_params, signs)
# #print("aggr_sig: ", aggr_sig)

credential["credential"] = aggr_sig
verify_proof = verify_pi_s(validator_params, commitments, cm, prevParams, prevVcerts, pi_s_old, include_indexes)
print("Verify pi_s: ", verify_proof)

disclose_index = [0,0]
disclose_attr = []
disclose_attr_enc = []
encoded_private_m = [19980512, 100000]
encoded_public_m = []
# proving the possession of AC (Off-chain by user) private_m, disclose_index, disclose_attr, disclose_attr_enc, public_m
Theta, aggr = ProveCred(validator_params, aggregate_vk, aggr_sig, encoded_private_m, disclose_index, disclose_attr, disclose_attr_enc, encoded_public_m)
(kappa, nu, rand_sig, proof, Aw, _timestamp) = Theta
# Aw, _timestamp, proof = proof_v
encoded_disclosed_attr = []
#Sending to SP_verify for verifying the proof. 
# SP_RequestService(credential, user_addr,disclose_index,aggr_sig,Theta,encoded_disclosed_attr,encoded_public_m,aggregate_vk)
tf = VerifyCred(validator_params, aggregate_vk, Theta, disclose_index, encoded_disclosed_attr, encoded_public_m)
print("Verify Cred : ",tf)
print(tf)

# # Identity Certificate
# vcert_title = "Identity Certificate"

# vcert = {"title":vcert_title, "attributes" : None, "commit": None, "signature": None}
# attributes = {}
# key1 = "msk"
# value1 = msk
# attributes.setdefault(key1, value1)
# key2 = "r"
# value2 = genRandom()
# attributes.setdefault(key2, value2)
# key3 = "name"
# value3 = "Justin"
# attributes.setdefault(key3, value3)
# key4 = "dob"
# value4 = "1998-05-12"
# attributes.setdefault(key4, value4)
			
# attribute = []
# encode_str = []

# # make order for schema order
# schemaOrder = ["msk", "name", "dob", "r"]
# # encode type 1: string, 2: int, 3: datetime
# # prv key
# attribute.append(attributes[key1])
# encode_str.append(2) # int
# # name
# attribute.append(attributes[key3])
# encode_str.append(1) # string
# # DOB
# _date = datetime.datetime.strptime(value4,"%Y-%m-%d").date()
# value = int(_date.strftime('%Y%m%d'))
# attribute.append(value)
# encode_str.append(3) # datetime
# # r
# attribute.append(attributes[key2])
# encode_str.append(2) # int

	
# encoded_attribute = encode_attributes(attribute, encode_str)
# q = len(schemaOrder)

# ca_params = ttp_setup(q-1, vcert_title) # exclude r.

# # commit is G1 point
# commit = GenCommitment(ca_params, encoded_attribute)

# zkpok = GenZKPoK(ca_params, [], [], [encoded_attribute], commit)

# # send for CA do verify
# encoded_attribute_verify = [encoded_attribute[1], encoded_attribute[2]]
# result  = VerifyZKPoK(ca_params, [], [], encoded_attribute_verify, commit, zkpok)
# #print("ZKPoK verification result: ", result)


# pubCP, mskCP = ttpKeyGen(ca_params)
# signature = SignCommitment(ca_params, mskCP, commit)
# issueVcert = (commit, signature)
# # print("pubCP: ", pubCP)
# pubkeyUncompress: G1Uncompressed = (FQO(pubCP[0].n),
#                               FQO(pubCP[1].n), 
#                               FQO(1))


# if(VerifyVcerts(ca_params, pubCP, signature, SHA256(commit)) == True):
#     vcert["attributes"] = attributes
#     vcert["commit"] = commit
#     vcert["signature"] = signature

# # print("pubkeyUncompress", i2osp(compress_G1(pubkeyUncompress),48).hex())
# # print("signature", {
# #     "r":  signature[0],
# #     "s":  signature[1],
# #     "r_g1": signature[2]
# # } )

# # commitUncompress: G1Uncompressed = (FQO(commit[0].n),
# #                               FQO(commit[1].n), 
# #                               FQO(1))
# # print("commitUncompress", i2osp(compress_G1(commitUncompress),48).hex())

# # print("vcert", vcert)

# # Income Certificate
# vcert_title_income = "Income Certificate"

# vcert_income = {"title":vcert_title_income, "attributes" : None, "commit": None, "signature": None}
# attributes_income = {}
# key1 = "msk"
# value1 = msk
# attributes_income.setdefault(key1, value1)
# key2 = "r"
# value2 = genRandom()
# attributes_income.setdefault(key2, value2)
# key5 = "salary"
# value5 = 100000
# attributes_income.setdefault(key5, value5)

# attribute_income = []
# encode_str_income = []

# # make order for schema order
# schemaOrder_income = ["msk", "salary", "r"]
# # encode type 1: string, 2: int, 3: datetime
# # prv key
# attribute_income.append(attributes_income[key1])
# encode_str_income.append(2) # int
# # salary
# attribute_income.append(attributes_income[key5])
# encode_str_income.append(2) # int
# # r
# attribute_income.append(attributes_income[key2])
# encode_str_income.append(2) # int

# encoded_attribute_income = encode_attributes(attribute_income, encode_str_income)
# q_income = len(schemaOrder_income)

# prevCombination = [vcert["title"]]
# prevParams = [ca_params]
# prevVcerts = [(vcert["commit"], vcert["signature"])]
# prevAttributes = [encoded_attribute]

# ca_params_income = ttp_setup(q_income-1, vcert_title_income) # exclude r.

# commit_income = GenCommitment(ca_params_income, encoded_attribute_income)
# #print("commit_income", commit_income)
# prevAttributes.append([attribute_income[0], attribute_income[-1]])

# zkpok_income = GenZKPoK(ca_params_income, prevParams, prevVcerts, prevAttributes, commit_income)

# # send for CA do verify income
# encoded_attribute_income_verify = [encoded_attribute_income[1]]

# result_income = VerifyZKPoK(ca_params_income, prevParams, prevVcerts, encoded_attribute_income_verify, commit_income, zkpok_income)
# #print("ZKPoK verification income result: ", result_income)

# pubCP2, mskCP2 = ttpKeyGen(ca_params_income)


# pubkeyUncompress2: G1Uncompressed = (FQO(pubCP2[0].n),
#                               FQO(pubCP2[1].n), 
#                               FQO(1))
# signature_income = SignCommitment(ca_params_income, mskCP2, commit_income)
# #print("signature_income", signature_income)
# issueVcertIncome = (commit_income, signature_income)
# # #print("Signature: ", signature_income)

# if(VerifyVcerts(ca_params_income, pubCP2, signature_income, SHA256(commit_income)) == True):
#     vcert_income["attributes"] = attributes_income
#     vcert_income["commit"] = commit_income
#     vcert_income["signature"] = signature_income

# ######################################
# ## create credential
# ######################################

# ac_title = "Loan Credential"
# credential = {"title": ac_title, "attributes" : attributes, "credential": None}
# q = 4 + 3 # schemaOrder = ["msk", "name", "dob", "r", "salary"], schemaOrderIncome = ["msk", "salary", "r"]
# params = setup(q, ac_title)
# (_, _, _, hs, _, _) = params
# nv = 3 #getTotalValidators(args.title)
# tv = 2 #getThresholdValidators(args.title)
# #q = getTotalAttributes(args.title)
# (sk, vk) = ttp_keygen(params, tv, nv)
# # #print("sk, vk", sk, vk)
# aggregate_vk = agg_key(params, vk)
# to = 2 #getThresholdOpeners(args.title) 
# no = 3 #getTotalOpeners(args.title)
# (opk, osk) = opener_keygen( params)
# (opk1, osk1) = opener_keygen(params)
# (opk2, osk2) = opener_keygen(params)
# opks = [opk, opk1, opk2]

# prevVcerts = [(vcert["commit"], vcert["signature"])]	
# prevParams = [ca_params, ca_params_income]
# all_encoded_attr = []
# prevParams.append(ca_params)
# prevVcerts.append((vcert_income["commit"], vcert_income["signature"]))
# all_encoded_attr.append(encoded_attribute)
# all_encoded_attr.append(encoded_attribute_income)

# combination = ["Identity Certificate", "Income Certificate"]
# include_indexes = [[1,0,0,1],[1,0,1]]

# Lambda, os = PrepareCredRequest(params, aggregate_vk, to, no, opks, prevParams, all_encoded_attr, include_indexes, public_m=[])
	
# # #print("Lambda: ", Lambda)
# # #print("os: ", os)

# (cm, commitments, pi_s, hp, C, pi_o, Dw, Ew, hr, bo) = Lambda
# #anything with "send" appended is making that particular variable as SC compatible.
# send_cm = (cm[0].n, cm[1].n)
# send_commitments = [(commitments[i][0].n, commitments[i][1].n) for i in range(len(commitments))]
# send_ciphershares= [([([C[i][j][0].coeffs[1].n,C[i][j][0].coeffs[0].n],[C[i][j][1].coeffs[1].n, C[i][j][1].coeffs[0].n]) for j in range(2)],) for i in range(len(C))]
# send_compressed_cipher = (send_commitments, send_ciphershares)
# private_m = []
# # schema = downloadSchema(title)
# # schemaOrder = downloadSchemaOrder(title)
# # for key in schemaOrder:
# #     if schema[key]['visibility'] == 'private':
# #         private_m.append(credential["attributes"][key])
# private_m.append(vcert["attributes"][key1])
# private_m.append(vcert["attributes"][key2])
# private_m.append(vcert_income["attributes"][key1])
# private_m.append(vcert_income["attributes"][key2])
# send_hp =  [[(hp[i][j-1][0].n, hp[i][j-1][1].n) for j in range(1, to)] for i in range(len(private_m))]
# send_hr = [(hr[i][0].n, hr[i][1].n) for i in range(len(hr))]
# send_bo = [([bo[i][0].coeffs[1].n,bo[i][0].coeffs[0].n],[bo[i][1].coeffs[1].n,bo[i][1].coeffs[0].n]) for i in range(len(bo))]
# send_Dw = [([Dw[i][0].coeffs[1].n,Dw[i][0].coeffs[0].n],[Dw[i][1].coeffs[1].n,Dw[i][1].coeffs[0].n]) for i in range(len(Dw))]
# send_Ew = [([Ew[i][0].coeffs[1].n,Ew[i][0].coeffs[0].n],[Ew[i][1].coeffs[1].n,Ew[i][1].coeffs[0].n]) for i in range(len(Ew))]
# send_compressed_G2Points = (send_Dw, send_Ew)
# send_vcerts = [((prevVcerts[i][0][0].n, prevVcerts[i][0][1].n), prevVcerts[i][1]) for i in range(len(prevVcerts))]

# pi_s = list(pi_s)
# # pi_s.append(combination)
# pi_s = tuple(pi_s)

# # #print("sending for verification", pi_s)
# public_m = []
# public_m.append(encoded_attribute[1])
# public_m.append(encoded_attribute[2])
# public_m.append(encoded_attribute_income[1])
# str_public_m = [str(public_m[i]) for i in range(len(public_m))]
# print("########## Requesting Credential #########")
# # print("prevVcerts", prevVcerts[0])

# print("pubkeyUncompress", i2osp(compress_G1(pubkeyUncompress),48).hex())
# print("pubkeyUncompress2", i2osp(compress_G1(pubkeyUncompress2),48).hex())
# commitUncompress: G1Uncompressed = (FQO(prevVcerts[0][0][0].n),
#                               FQO(prevVcerts[0][0][1].n), 
#                               FQO(1))
# commitUncompress2: G1Uncompressed = (FQO(prevVcerts[1][0][0].n),
#                               FQO(prevVcerts[1][0][0].n), 
#                               FQO(1))
# print("commitUncompress", i2osp(compress_G1(commitUncompress),48).hex())
# print("commitUncompress2", i2osp(compress_G1(commitUncompress2),48).hex())


# print("signature", {
#     "r":  prevVcerts[0][1][0],
#     "s":  prevVcerts[0][1][1],
#     # "r_g1": prevVcerts[0][1][2],
# } )

# print("signature2", {
#     "r":  prevVcerts[1][1][0],
#     "s":  prevVcerts[1][1][1],
#     # "r_g1": prevVcerts[1][1][2]
# } )

# print("sending for verification pi proof", pi_s)
# print("cm_compressed", i2osp(compress_G1((send_cm[0], send_cm[1], FQO(1))),48).hex())
# print("hs_compressed", [i2osp(compress_G1((hs[i][0].n, hs[i][1].n, FQO(1))),48).hex() for i in range(len(hs))])
# # tx_hash = request_contract.functions.RequestCred(title, send_vcerts, send_cm, send_compressed_cipher, send_hp, send_hr, send_bo, pi_s, pi_o, send_compressed_G2Points, str_public_m).transact({'from':user_addr})
# # compressCommitments = [i2osp(compress_G1((send_vcerts[i][0][0],send_vcerts[i][0][1], FQO(1))),48).hex() for i in range(len(send_vcerts))]
# #send_cm, send_compressed_cipher, send_hp, send_hr, send_bo, pi_s, pi_o, send_compressed_G2Points, str_public_m)
# # validator 1
# Lambda2 = (cm, commitments)
# # #print("sk", sk)
# blind_sig = BlindSignAttr(params, sk[0], Lambda2, public_m)

# send_h = [blind_sig[0][0].n, blind_sig[0][1].n]
# send_t = [blind_sig[1][0].n, blind_sig[1][1].n]

# print("send_h_compress: ", i2osp(compress_G1((send_h[0], send_h[1], FQO(1))),96).hex())
# # #print("send_t: ", send_t)

# h = (FQ(send_h[0]), FQ(send_h[1]))
# t = (FQ(send_t[0]), FQ(send_t[1]))

# blind_sig = (h, t)
# sigma = Unblind(params, aggregate_vk, blind_sig, os)
# # #print("sigma: ", sigma)

# # validator 2
# # Lambda2 = (cm, commitments)
# # #print("sk", sk)
# blind_sig2 = BlindSignAttr(params, sk[1], Lambda2, public_m)

# send_h2 = [blind_sig2[0][0].n, blind_sig2[0][1].n]
# send_t2 = [blind_sig2[1][0].n, blind_sig2[1][1].n]

# # #print("send_h: ", send_h2)
# # #print("send_t: ", send_t2)

# h2 = (FQ(send_h2[0]), FQ(send_h2[1]))
# t2 = (FQ(send_t2[0]), FQ(send_t2[1]))

# blind_sig2 = (h2, t2)
# sigma2 = Unblind(params, aggregate_vk, blind_sig2, os)
# # #print("sigma: ", sigma)

# signs = []
# signs.append(sigma)
# signs.append(sigma2)

# aggr_sig = AggCred(params, signs)
# # #print("aggr_sig: ", aggr_sig)

# credential["credential"] = aggr_sig
# # verify_proof = verify_pi_s(params, commitments, cm, prevParams, prevVcerts, pi_s, include_indexes)
# # print("Verify pi_s: ", verify_proof)
# ##############################################
# ## RequestService
# ##############################################

# # title = credential["title"]
# # #print("The available policies are : ")
# # 	total_policies = verify_contract.functions.gettotalPolicies(title).call()
# # 	for i in range(total_policies):
# # 		policy = verify_contract.functions.getPolicy(title, i+1).call()
# # 		#print("choose "+str(i+1)+" for : ", str(policy))
# # 	policy_id = int(input("Choose any policy : "))
# # 	disclose_index = verify_contract.functions.getPolicy(title, policy_id).call()

# ac_encode_str = []
# private_m = []
# # 	schema = downloadSchema(title)
# # 	schemaOrder = downloadSchemaOrder(title)
# # 	encoding = downloadEncoding(title)
# # 	for key in schemaOrder:
# # 		if schema[key]['visibility'] == 'private':
# # 			private_m.append(credential["attributes"][key])
# # 			ac_encode_str.append(encoding[key])
# # 	disclose_attr = [private_m[i] for i in range(len(private_m)) if disclose_index[i]==1]
# # 	str_disclose_attr = [str(disclose_attr[i]) for i in range(len(disclose_attr))]

# private_m.append(vcert["attributes"][key1])
# private_m.append(vcert["attributes"][key2])
# private_m.append(vcert_income["attributes"][key1])
# private_m.append(vcert_income["attributes"][key2])

# ac_encode_str.append(2)
# ac_encode_str.append(2)
# ac_encode_str.append(2)
# ac_encode_str.append(2)

# # 	params = downloadACParams(title)
# _, o, _, _, _, _ = params

# # 	encoded_private_m = encode_attributes(private_m, ac_encode_str)
# encoded_private_m = []
# encoded_private_m.append(encoded_attribute[0])
# encoded_private_m.append(encoded_attribute[3])
# encoded_private_m.append(encoded_attribute_income[0])
# encoded_private_m.append(encoded_attribute_income[2])
# # 	encoded_disclose_attr = [encoded_private_m[i] for i in range(len(encoded_private_m)) if disclose_index[i]==1]
# # 	disclose_attr_enc = [ac_encode_str[i] for i in range(len(ac_encode_str)) if disclose_index[i]==1]

# # 	public_m = []
# # 	public_m_encoding = []
# # 	for key in schemaOrder:
# # 		if schema[key]['visibility'] == 'public':
# # 			public_m.append(credential["attributes"][key])
# # 			public_m_encoding.append(schema[key]["type"])
# # 	encoded_public_m = []
# # 	for i in range(len(public_m)):
# # 		if public_m_encoding[i] == 1:
# # 			encoded_public_m.append(int.from_bytes(sha256(public_m[i].encode("utf8").strip()).digest(), "big") % o)
# # 		else:
# # 			encoded_public_m.append(public_m[i])

# # 	aggregate_vk = getAggregateVerificationKey(title)

# encoded_public_m = []
# encoded_public_m.append(encoded_attribute[1])
# encoded_public_m.append(encoded_attribute[2])
# encoded_public_m.append(encoded_attribute_income[1])
# disclose_index = [0,0]
# disclose_attr = [private_m[i] for i in range(len(private_m)) if disclose_index[i]==1]
# disclose_attr_enc = [ac_encode_str[i] for i in range(len(ac_encode_str)) if disclose_index[i]==1]
# disclose_attr = []
# # proving the possession of AC (Off-chain by user) private_m, disclose_index, disclose_attr, disclose_attr_enc, public_m
# Theta, aggr = ProveCred(params, aggregate_vk, aggr_sig, encoded_private_m, disclose_index, disclose_attr, disclose_attr_enc, encoded_public_m)
# (kappa, nu, rand_sig, proof, Aw, _timestamp) = Theta
# # Aw, _timestamp, proof = proof_v
# encoded_disclosed_attr = encode_attributes(disclose_attr, disclose_attr_enc)
# #Sending to SP_verify for verifying the proof. 
# # SP_RequestService(credential, user_addr,disclose_index,aggr_sig,Theta,encoded_disclosed_attr,encoded_public_m,aggregate_vk)
# tf = VerifyCred(params, aggregate_vk, Theta, disclose_index, encoded_disclosed_attr, encoded_public_m)
# print("Verify Cred : ",tf)
# print(tf)