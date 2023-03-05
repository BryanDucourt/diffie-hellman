rm -rf ./build
mkdir "build"
cd build || exit
cmake ..
make
cp ./Client/DH_CLIENT ../client_compose/
cp ./Server/DH_SERVER ../server_compose/

cd ..
docker-compose build
docker-compose up -d