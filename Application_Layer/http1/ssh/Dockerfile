FROM python:3
WORKDIR /usr/src/app
COPY . .
RUN pip3 install paramiko
ENTRYPOINT ["python3", "-u", "client.py"]