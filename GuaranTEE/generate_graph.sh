#!/bin/bash
if test -f "valid_cfg.dot"; then
    printf "Generating graph... "
    dot -Tpdf -o valid_cfg.pdf valid_cfg.dot
    printf "Done\n"
else
    printf "valid_cfg.dot does not exist. Please run the server first\n"
fi
