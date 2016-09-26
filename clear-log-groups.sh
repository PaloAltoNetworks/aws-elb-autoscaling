#!/bin/bash

# Use this script to clear all the log-groups in your current region

trap ctrl_c INT

function ctrl_c() {
    echo "** Exiting due to CTRL+C **"
    exit -1
}

echo "WARNING: This will destroy all the log-groups in your region"
echo "WARNING: Waiting for 10 seconds before kicking off..."

read -r -p "Are you sure? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 
        echo "Proceeding with cloud watch delete..."
        ;;
    *)
        exit 0
        ;;
esac


echo "Running aws log describe-log-groups ..."
echo "Press CTRL+C to exit..."
for i in `aws logs describe-log-groups --output text | awk -F " " '{ print $2}' | awk -F ":" '{print $7}'`
do
    echo "Deleting LogGroupName: $i"
    aws logs delete-log-group --log-group-name $i
done
    
