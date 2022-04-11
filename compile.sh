#!/bin/bash

docker build -t ns3-cv2x-compiler dockerCompile

# Compile ns-3_c-v2x and launch a bash shell after that
# docker run --rm --user $(id -u):$(id -g) -it -v $(pwd):/ns3 ns3-cv2x-compiler bash
docker run --rm -it -v $(pwd):/ns3 ns3-cv2x-compiler bash
