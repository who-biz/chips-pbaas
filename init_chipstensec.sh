#!/bin/bash
#
# Initialization script for first-run, to place config file in proper location.
# Removes need to run a vrsctest daemon prior to launching 'chipstensec' chain
#
# @author who-biz

FILE="$PWD/conf/7733e5dcf2ed716dcb20ebf375ac45239c1902af.conf"
rpcuser="user"
rpcpass="password"
datadir="$HOME/.verustest/pbaas/7733e5dcf2ed716dcb20ebf375ac45239c1902af/"
newconf="$datadir7733e5dcf2ed716dcb20ebf375ac45239c1902af.conf"

if [[ -f $FILE ]]; then
    rpcuser="rpcuser=$rpcuser$RANDOM$RANDOM$RANDOM"
    rpcpass="rpcpassword=$rpcpass$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM"
    mkdir -p $datadir
    cp $FILE $datadir
    echo "$rpcuser" >> $newconf
    echo "$rpcpass" >> $newconf
    echo "Attempting to start CHIPS daemon..."
    $PWD/src/verusd -chain=chipstensec &
else
    echo "File at location $FILE not found, or is a directory etc..."
fi
