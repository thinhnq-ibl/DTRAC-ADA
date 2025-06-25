#!/bin/bash

# Define the path to the virtual environment activation script
VENV_ACTIVATE="./.venv/bin/activate"

# Function to check if venv exists and is executable
check_venv() {
    if [ ! -f "$VENV_ACTIVATE" ]; then
        echo "Virtual environment activation script not found at $VENV_ACTIVATE"
        echo "Expected virtual environment in .venv directory"
        exit 1
    elif [ ! -x "$VENV_ACTIVATE" ]; then
        echo "Virtual environment activation script is not executable. Making it executable..."
        chmod +x "$VENV_ACTIVATE"
    fi
    echo "Virtual environment is ready."
}


# Check for venv before starting
check_venv

############### A D M I N ############################################## INITIALIZATION #####################################################
command0='rm -rf ROOT/'
gnome-terminal --title="Deleting root" -- bash -c "$command0;"

sleep 1

command1='python3 AttributeCertifier.py --title "Identity Certificate" --name IdP --req-ip 127.0.0.1 --req-port 3001  --open-ip 127.0.0.1 --open-port 7001'
command2='python3 AttributeCertifier.py --title "Income Certificate" --name Employer --req-ip 127.0.0.1 --req-port 3002  --open-ip 127.0.0.1 --open-port 7002 --dependency "Identity Certificate"'
command3='truffle migrate --reset –compile-all'

# Activate venv for python commands within gnome-terminal
gnome-terminal --title="Identity CA" -- bash -c "source $VENV_ACTIVATE && $command1 < Identity_input.txt; exec bash"
sleep 1
gnome-terminal --title="Income CA" -- bash -c "source $VENV_ACTIVATE && $command2 < Income_input.txt; exec bash"
sleep 1
# Activate venv for truffle command
gnome-terminal --title="SC Deploying" -- bash -c "source $VENV_ACTIVATE && $command3 > SC_output.txt;"
# bash avoided at tail end to exit the tab after execution
sleep 10 #waiting for SC deployment

# Check if SC_output.txt exists and has enough lines
if [ ! -f SC_output.txt ] || [ $(wc -l < SC_output.txt) -lt 164 ]; then
    echo "Error: SC_output.txt not found or incomplete. Deployment might have failed."
    # Optionally exit or handle the error appropriately
    # exit 1
fi


# Extract addresses using sed, provide default if extraction fails
Opening=$(sed -n '160p' SC_output.txt)
Issue=$(sed -n '161p' SC_output.txt)
Request=$(sed -n '162p' SC_output.txt)
Params=$(sed -n '163p' SC_output.txt)
Verify=$(sed -n '164p' SC_output.txt)

# Check if addresses were extracted
if [ -z "$Params" ] || [ -z "$Request" ] || [ -z "$Issue" ] || [ -z "$Opening" ]; then
    echo "Warning: Could not extract all contract addresses from SC_output.txt."
    # Handle this case, maybe provide defaults or exit
fi


# Use extracted variables directly in the command string
command4="python3 ProtocolInitiator_DeployContracts.py --params-address '$Params' --request-address '$Request' --issue-address '$Issue' --opening-address '$Opening'"

gnome-terminal --title="ProtocolInitiator_DeployContracts" -- bash -c "source $VENV_ACTIVATE && $command4;"
sleep 5

command5='python3 ProtocolInitiator_AC_Setup.py --title "Loan Credential" --name Loaner --ip 127.0.0.1 --port 4000 --dependency "Identity Certificate" "Income Certificate"'

gnome-terminal --title="ProtocolInitiator_AC_Setup" -- bash -c "source $VENV_ACTIVATE && $command5 < ProtocolInitiator_input.txt;"
sleep 5

command6='python3 ProtocolInitiator_UpdateCAInformation.py --titles "Identity Certificate" "Income Certificate" --address 0xE279a5e0DEb02eDe68876bea8206EeFb2Ab0E96C --rpc-endpoint "http://127.0.0.1:7545"'

gnome-terminal --title="ProtocolInitiator_UpdateCAInformation" -- bash -c "source $VENV_ACTIVATE && $command6;"
sleep 5

command7='python3 ProtocolInitiator_AnonymousCredentials.py --title "Loan Credential" --address 0xE279a5e0DEb02eDe68876bea8206EeFb2Ab0E96C --validator-addresses 0x444D3aa9426Ca8e339d607bF53262A8B524B844e 0x2D0B894312087b3BF55e4432871b6FD3CC8c180A 0x5126e167868d403dba7DbC5a28bA0e5ACbb086C0 --opener-addresses 0x202870f3671F1d6B401693FBcF66082781D1958F 0x34aB8f91ef8524a9eCF47D2eC6ab1DBdC3a2D704 0xdedCA5790B8899dA5168a4D34b171A8294D0Fb5F --rpc-endpoint "http://127.0.0.1:7545"'

gnome-terminal --title="ProtocolInitiator_AnonymousCredentials" -- bash -c "source $VENV_ACTIVATE && $command7;"
sleep 5

############### ############################################## #####################################################

command8='python3 Validator.py --title "Loan Credential" --id 1 --address 0x444D3aa9426Ca8e339d607bF53262A8B524B844e --rpc-endpoint "http://127.0.0.1:7545"'
command9='python3 Validator.py --title "Loan Credential" --id 2 --address 0x2D0B894312087b3BF55e4432871b6FD3CC8c180A --rpc-endpoint "http://127.0.0.1:7545"'
command10='python3 Validator.py --title "Loan Credential" --id 3 --address 0x5126e167868d403dba7DbC5a28bA0e5ACbb086C0 --rpc-endpoint "http://127.0.0.1:7545"'

command11='python3 Opener.py --title "Loan Credential" --id 1 --ip 127.0.0.1 --port 8001 --address 0x202870f3671F1d6B401693FBcF66082781D1958F --rpc-endpoint "http://127.0.0.1:7545"'
command12='python3 Opener.py --title "Loan Credential" --id 2 --ip 127.0.0.1 --port 8002 --address 0x34aB8f91ef8524a9eCF47D2eC6ab1DBdC3a2D704 --rpc-endpoint "http://127.0.0.1:7545"'
command13='python3 Opener.py --title "Loan Credential" --id 3 --ip 127.0.0.1 --port 8003 --address 0xdedCA5790B8899dA5168a4D34b171A8294D0Fb5F --rpc-endpoint "http://127.0.0.1:7545"'

gnome-terminal --title="Validator 1" -- bash -c "source $VENV_ACTIVATE && $command8; exec bash"
gnome-terminal --title="Validator 2" -- bash -c "source $VENV_ACTIVATE && $command9; exec bash"
gnome-terminal --title="Validator 3" -- bash -c "source $VENV_ACTIVATE && $command10; exec bash"

gnome-terminal --title="Opener 1" -- bash -c "source $VENV_ACTIVATE && $command11; exec bash"
gnome-terminal --title="Opener 2" -- bash -c "source $VENV_ACTIVATE && $command12; exec bash"
gnome-terminal --title="Opener 3" -- bash -c "source $VENV_ACTIVATE && $command13; exec bash"

sleep 15

# Use extracted variable Verify
#command14="python3 SP.py --title \"Loan Service\" --name Bank --address 0xB1A0d85CFeA6ce282729adb7e66CD69f57DC3245 --verify-address '$Verify' --rpc-endpoint \"http://127.0.0.1:7545\" --accepts \"Loan Credential\""

# Uncomment one of the following if needed, ensuring venv activation
# gnome-terminal --title="Service Provider" -- bash -c "source $VENV_ACTIVATE && $command14 < SP_input.txt; exec bash"
# gnome-terminal --title="Service Provider" -- bash -c "source $VENV_ACTIVATE && $command14; exec bash"

sleep 15

#command15='python3 User.py --unique-name user1 --address 0x1A1684c3027eA12046155013BfC5518C65dD5943 --rpc-endpoint "http://127.0.0.1:7545"'
# Uncomment one of the following if needed, ensuring venv activation
# gnome-terminal --title="User 1" -- bash -c "source $VENV_ACTIVATE && $command15 < User_input.txt; exec bash"
# gnome-terminal --title="User 1" -- bash -c "source $VENV_ACTIVATE && $command15; exec bash"

# Activate venv for the final python command (if not run in gnome-terminal)
# Check if Verify address was extracted
#if [ -z "$Verify" ]; then
#    echo "Error: Verify address not found for final User.py command."
    # exit 1 # Or handle error
#else
    # Construct the final command using extracted Verify address
#    final_command="python3 User.py --title \"Loan Service\" --name Bank --address 0xB1A0d85CFeA6ce282729adb7e66CD69f57DC3245 --verify-address '$Verify' --accepts \"Loan Credential\" --unique-name user1 --address 0x1A1684c3027eA12046155013BfC5518C65dD5943 --rpc-endpoint \"http://127.0.0.1:7545\""
    # Execute the command within the venv in the current shell
#    source "$VENV_ACTIVATE" && $final_command
    # Deactivate if needed, though script end will handle it
    # deactivate
#fi

echo "Script finished."
