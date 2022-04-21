#!/bin/bash
printf "Sending valid server requests:\n"
printf "Send signing request 1... "
curl -k -X POST -d 'hash=4355A46B19D348DC2F57C046F8EF63D4538EBB936000F3C9EE954A27460DD865' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 2... "
curl -k -X POST -d 'hash=53c234e5e8472b6ac51c1ae1cab3fe06fad05' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 5... "
curl -k -X POST -d 'hash=f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 5... "
curl -k -X POST -d 'hash=f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 5... "
curl -k -X POST -d 'hash=f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 6... "
curl -k -X POST -d 'wronghash=f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06' https://localhost:4433/signature.html >& /dev/null
printf "Done\n"
printf "Send signing request 7... "
curl -k https://localhost:4433/admin.html >& /dev/null
printf "Done\n"
