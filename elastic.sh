#!/bin/bash

if [ -n "$(docker ps -q)" ]; then
    docker rm -f $(docker ps -q)
fi
docker volume rm elastic_elastic_data

ifname=$(netstat -rn |grep 0.0.0.0 --max-count 1|awk '{print$8}')
host=$(ifconfig $ifname | grep inet -w|awk '{print$2}')
VERSION=9.3.0
DIR="$HOME/elastic/"
URL="https://$host:9200"
WORKINGDIR="$PWD/logstash-pipeline.tar.gz"
RETRIES=4
COUNT=1

IMAGES=(
  "docker.elastic.co/elasticsearch/elasticsearch:$VERSION"
    "docker.elastic.co/logstash/logstash:$VERSION"
      "docker.elastic.co/kibana/kibana:$VERSION"
      )

while true; do
  ALL_INSTALLED=true
    for IMG in "${IMAGES[@]}"; do
      VENDOR=$(docker image inspect "$IMG" --format '{{.Config.Labels.vendor}}' 2>/dev/null)
      if [ "$VENDOR" != "Elastic" ]; then
        echo "Installing/Fixing: $IMG"
        docker pull "$IMG"
        ALL_INSTALLED=false
      else
        echo "Verified: $IMG"
      fi
    done

    if [ "$ALL_INSTALLED" = true ]; then
      echo "All images are verified and installed."
      break
    fi
    echo "Some images failed. Retrying in 5 seconds..."
    sleep 5
done

ELASTIC_IMAGE=$(docker image inspect docker.elastic.co/elasticsearch/elasticsearch:9.3.0 | grep '"vendor"' | awk '{print $2}' | tr -d '",')
if [ $ELASTIC_IMAGE != "Elastic" ]; then
  docker pull docker.elastic.co/elasticsearch/elasticsearch:9.3.0
else
 printf "Elasstic Image Exists\n"
 LOGSTASH_IMAGE=$(docker image inspect docker.elastic.co/logstash/logstash:9.3.0 | grep '"vendor"' | awk '{print $2}' | tr -d '",')
 if [ $LOGSTASH_IMAGE != "Elastic" ]; then
   docker pull docker.elastic.co/logstash/logstash:9.3.0
 else
   printf "Logstash Image Exists\n"
   KIBANA_IMAGE=$(docker image inspect docker.elastic.co/kibana/kibana:9.3.0 | grep '"vendor"' | awk '{print $2}' | tr -d '",')
    if [ $KIBANA_IMAGE != "Elastic" ]; then
      docker pull docker.elastic.co/kibana/kibana:9.3.0
    else
      printf "Kibana Image Exists\n"
    fi 
 fi

 if [ -d "$DIR" ]; then
       read -p "Directory '$DIR' already exists. Delete and recreate? [y/N]: " choice
       case "$choice" in 
           [yY][eE][sS]|[yY]) 
               rm -rf "$DIR"
               echo "Existing directory removed."
               ;;
           *)
               echo "Keeping existing directory."
               ;;
               esac
 fi
 if [ ! -d "$DIR" ]; then
    mkdir "$DIR"
        echo "Directory created at $DIR."
 fi
 cd $DIR
 # Create the Certificate Authority (CA)
 docker run --rm -u $(id -u):$(id -g) -v $(pwd):$DIR \
  docker.elastic.co/elasticsearch/elasticsearch:9.3.0 \
    bin/elasticsearch-certutil ca --out $DIR/elastic-stack-ca.p12 --pass ""

    # Create the Certificates using the CA
    docker run --rm -u $(id -u):$(id -g) -v $(pwd):$DIR \
      docker.elastic.co/elasticsearch/elasticsearch:9.3.0 \
        bin/elasticsearch-certutil cert --ca $DIR/elastic-stack-ca.p12 --ca-pass "" --out $DIR/elastic-certificates.p12 --pass ""
 chmod 644 $DIR/elastic-certificates.p12

 #Create Kibana cert and key
 openssl pkcs12 -in $DIR/elastic-certificates.p12 -out $DIR/kibana-server.key -nocerts -nodes
 openssl pkcs12 -in $DIR/elastic-certificates.p12 -out $DIR/kibana-server.crt -clcerts -nokeys
 chmod 644 $DIR/kibana-server.key
 chmod 644 $DIR/kibana-server.crt

 set_hostname=$(hostname)
 #Add Elastic config
 cat <<EOF | tee elastic.yml > /dev/null
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:9.3.0
    volumes:
    - elastic_data:/usr/share/elasticsearch/data
    - ./elastic-certificates.p12:/usr/share/elasticsearch/config/elastic-certificates.p12
    environment:
    - discovery.type=single-node
    - network.host=0.0.0.0
    - network.publish_host=0.0.0.0
    - xpack.license.self_generated.type=trial
    - node.name=elasticsearch
    - cluster.name=elastic_cluster1
    - bootstrap.memory_lock=true
    - ES_JAVA_OPTS=-Xms1g -Xmx1g
    - xpack.security.enabled=true
    - ELASTIC_USERNAME=elastic
    - ELASTIC_PASSWORD=Sanjay1234
    - xpack.security.http.ssl.enabled=true
    - xpack.security.http.ssl.keystore.path=elastic-certificates.p12
    - xpack.security.http.ssl.truststore.path=elastic-certificates.p12
    - xpack.security.transport.ssl.enabled=true
    - xpack.security.transport.ssl.keystore.path=elastic-certificates.p12
    - xpack.security.transport.ssl.truststore.path=elastic-certificates.p12
    - xpack.security.transport.ssl.verification_mode=certificate
    networks:
    - elastic_network
    ports:
        - target: 9200
          published: 9200
          protocol: tcp
          mode: ingress
    deploy:
      placement:
        constraints:
        - node.hostname == $set_hostname
volumes:
  elastic_data: null
networks:
  elastic_network:
    external: true
EOF
 echo "elastic.yml created in $DIR"

 #Add Kibana config
 cat <<EOF | tee kibana.yml > /dev/null
services:
  kibana:
    image: docker.elastic.co/kibana/kibana:9.3.0
    volumes:
    - ./elastic-certificates.p12:/usr/share/kibana/config/elastic-certificates.p12:ro
    - ./kibana-server.crt:/usr/share/kibana/config/kibana-server.crt:ro
    - ./kibana-server.key:/usr/share/kibana/config/kibana-server.key:ro
    environment:
    - SERVER.NAME=kibana
    - SERVER.HOST="0.0.0.0"
    - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
    - SERVER_SSL_ENABLED=true
    - SERVER_SSL_CERTIFICATE=/usr/share/kibana/config/kibana-server.crt
    - SERVER_SSL_KEY=/usr/share/kibana/config/kibana-server.key
    - XPACK_SECURITY_ENABLED=true
    - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY="something_at_least_32_characters"
    - XPACK_SECURITY_ENCRYPTIONKEY="something_at_least_32_characters_long"
    - XPACK_REPORTING_ENCRYPTIONKEY="something_at_least_32_characters_long"
    - ELASTICSEARCH.SSL_TRUSTSTORE_PATH=/usr/share/kibana/config/elastic-certificates.p12
    - ELASTICSEARCH.SSL_VERIFICATIONMODE=certificate
    - ELASTICSEARCH_SSL_TRUSTSTORE_PASSWORD=""
    - ELASTICSEARCH_SSL_VERIFICATIONMODE=none
    - ELASTICSEARCH_USERNAME=kibana_system
    - ELASTICSEARCH_PASSWORD=Sanjay12345
    ports: [5601:5601]
    networks:
       - elastic_network
    deploy:
      placement:
        constraints:
        - node.hostname == $set_hostname 
volumes:
  kibana_data: null
networks:
  elastic_network:
    external: true
EOF
 echo "kibana.yml created in $DIR"

 #Add Logstash config
 cat <<EOF | tee logstash.yml > /dev/null
services:
  logstash:
    image: docker.elastic.co/logstash/logstash:9.3.0
    volumes:
      - ./elastic-certificates.p12:/usr/share/logstash/config/cert/elastic-certificates.p12:ro
      - $HOME/.persistent/logstash/pipeline:/usr/share/logstash/config/pipeline
      - $HOME/.persistent/logstash/config/pipelines.yml:/usr/share/logstash/config/pipelines.yml
    environment:
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports: [6514:6514/tcp,1515:1515/tcp,9030:9030/tcp,7654:7654/tcp,9004:9004/udp,6789:6789/udp,1234:1234/udp,5678:5678/udp,5145:5145/udp,5006:5006/tcp,1789:1789/udp,5044:5044/tcp]
    networks:
      - elastic_network
    deploy:
      placement:
        constraints:
        - node.hostname == $set_hostname
networks:
  elastic_network:
    external: true
EOF
 echo "logstash.yml created in $DIR"

 #untaring the Logstash test directories
 if [ -f "$WORKINGDIR" ]; then
     echo "$FILE exists and is a regular file."
     tar -zxvf $WORKINGDIR -C ~/
   else
     echo "$FILE does not exist or is not a regular file."
 fi

 docker network create --attachable elastic_network
 docker compose -f $DIR/elastic.yml up -d
 sleep 30

 #Test Elastic is up
 TEMP_BODY_FILE=$(mktemp)
 HTTP_STATUS=$(curl -k -s -o /dev/null -u elastic:Sanjay1234 -w "%{http_code}" "$URL")

 # Check if the captured HTTP status is 200
 while [ $COUNT -le $RETRIES ]; do
   if [ "$HTTP_STATUS" == "200" ]; then
       echo "Received HTTP 200 OK. Setting Kibana user password..."
       curl -k -u elastic:Sanjay1234 -XPOST "$URL/_security/user/kibana_system/_password?pretty"  -H "Content-Type: application/json"  -d '{ "password" : "Sanjay12345" }'
       echo "Creating Index 'forensics'"
       curl -k -u elastic:Sanjay1234 -XPUT "$URL/forensics"
       echo "Bringing up Kibana and Logstash in 10..."
       sleep 10
       docker compose -f $DIR/kibana.yml up -d
       docker compose -f $DIR/logstash.yml up -d
       break
   else
       echo "Did not receive HTTP 200 OK. Status code was: $HTTP_STATUS"
       HTTP_STATUS=$(curl -k -s -o /dev/null -u elastic:Sanjay1234 -w "%{http_code}" "$URL")
   fi
   sleep 30
   ((COUNT++))
 done
 rm "$TEMP_BODY_FILE"

 #Injecting some test data
 printf "Sleeping for 60s and then generating some Suricata events through logstash\n"
 for i in {1..60}; do echo -n "."; sleep 1; done; echo ""
 ~/.persistent/logstash/pipeline/suricata/resources/suricata_script.sh
 printf "\nSleeping for another 40\n"
 for i in {1..40}; do echo -n "."; sleep 1; done; echo ""
 curl -XGET -k -u elastic:Sanjay1234 "$URL/_cat/count/forensics"
fi
