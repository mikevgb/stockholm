#!/bin/bash
docker stop stockholm
docker rm stockholm
#docker system prune --all

docker build -t stockholm .
docker run --name stockholm -d stockholm

docker exec -it stockholm bash