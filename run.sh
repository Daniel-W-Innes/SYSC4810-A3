docker build -t a3 .
docker rm -f a3
#echo `$(dirname $(realpath $0))`/sensitive_files:/sensitive_files
echo `$(realpath $0)`
echo `$(dirname $(realpath $0))`
#docker run --name a3 -v `dirname $SCRIPT`/sensitive_files:/sensitive_files -it a3