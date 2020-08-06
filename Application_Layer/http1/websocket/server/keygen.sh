openssl req -subj "/C=NL/ST=None/L=None/O=Localio/OU=Org/CN=localhost" -newkey rsa:4096 -nodes -keyout domain.key -x509 -days 365 -out domain.crt 
# sudo mkdir /usr/local/share/ca-certificates/self-signed
# sudo cp domain.crt /usr/local/share/ca-certificates/self-signed/domain.crt
# sudo update-ca-certificates