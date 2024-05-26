#!/bin/bash

sudo docker build -t docker.io/isilincoln/gnbsim:demo -f Dockerfile .
sudo docker push docker.io/isilincoln/gnbsim:demo
