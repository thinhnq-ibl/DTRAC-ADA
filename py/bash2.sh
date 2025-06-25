#!/bin/bash


command14='python3 SP.py --title "Loan Service" --name Bank --address 0xB1A0d85CFeA6ce282729adb7e66CD69f57DC3245 --verify-address $(sed -n '164p' SC_output.txt) --rpc-endpoint "http://127.0.0.1:7545" --accepts "Loan Credential"'

gnome-terminal --title="Service Provider" -- bash -c "source ./.venv/bin/activate && $command14 < SP_input.txt; bash"

sleep 15

command15='python3 User.py --unique-name user1 --address 0x1A1684c3027eA12046155013BfC5518C65dD5943 --rpc-endpoint "http://127.0.0.1:7545"'
gnome-terminal --title="User 1" -- bash -c "source ./.venv/bin/activate && $command15 < User_input.txt; bash"



