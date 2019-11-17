cd /home/scott/src/k8oauth2

mvn package

docker build . -t scottschwab/basicauth:0.1  

docker push scottschwab/basicauth:0.1

kubectl delete -f ${PWD}/testing.yml

kubectl create -f ${PWD}/testing.yml
