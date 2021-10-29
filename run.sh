docker build -t a3 .
if docker ps -a | grep -q 'a3'; then
   docker rm -f a3
fi
# shellcheck disable=SC2046
docker run --name a3 -v $(pwd)/sensitive_files/:/sensitive_files/ -it --rm a3