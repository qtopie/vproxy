#!/bin/bash
pids=""
for i in {1..3}; do
    ./bin/vproxy ./bin/test_google > /tmp/test_google_$i.log 2>&1 &
    pids="$pids $!"
done
wait $pids
for i in {1..3}; do
    tail -n 2 /tmp/test_google_$i.log
done
