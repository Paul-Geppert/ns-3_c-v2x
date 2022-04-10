#!/bin/bash

docker build -t ns3-cv2x-scanner dockerScan

# Compile ns-3_c-v2x and launch a bash shell after that
docker run --rm -it -v $(pwd):/ns3 ns3-cv2x-scanner bash
