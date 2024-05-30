#!/bin/bash

sudo docker build -t docker.io/isilincoln/echo:demo -f Dockerfile .
sudo docker push docker.io/isilincoln/echo:demo
