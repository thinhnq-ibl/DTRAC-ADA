import argparse
import os
import pickle
#change all address
# python3 ProtocolInitiator_DeployContracts.py --params-address 0xBC15B02Fde1E6332B0227c21dCFd7B9b037F31A8 --request-address 0x37b495514722a93Dcef556b1E4ea0E25e88Ad5fF --issue-address 0xb2Fd49A4eB882a8b5D292EE3eb9a8aA5f71cB2a2 --opening-address 0x69616c96D5F15f1270DeaE8ec07D49A406457cfD


parser = argparse.ArgumentParser(description="Smart Contracts Deployment")
# parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which Protocol Initiator is running.")
parser.add_argument("--params-address", type=str, default = None, required = True,  help= "The blockchain address at which params contract is deployed.")
parser.add_argument("--request-address", type=str, default = None, required = True,  help= "The blockchain address at which request contract is deployed.")
parser.add_argument("--issue-address", type=str, default = None, required = True,  help= "The blockchain address at which issue contract is deployed.")
parser.add_argument("--opening-address", type=str, default = None, required = True,  help= "The blockchain address at which opening contract is deployed.")
# parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a client is connected to blockchain network.")
args = parser.parse_args()

mode = 0o777
root_dir = os.path.join(os.getcwd(), "ROOT")
try:
	os.mkdir(root_dir, mode = mode)
except FileExistsError as e:
	pass

def uploadAddresses(address, filename):
	file_path = os.path.join(root_dir, filename)
	f = open(file_path,'wb')
	pickle.dump(address, f)
	f.close()

#print(args.params_address)
#print("Displaying Output as: % s" % args.params_address)
uploadAddresses(args.params_address, "params_address.pickle")
uploadAddresses(args.request_address, "request_address.pickle")
uploadAddresses(args.issue_address, "issue_address.pickle")
uploadAddresses(args.opening_address, "opening_address.pickle")