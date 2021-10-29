docker build -t a3 .
docker rm -f a3
# shellcheck disable=SC2046
docker run --name a3 -v $(pwd)/sensitive_files/:/sensitive_files/ -it a3