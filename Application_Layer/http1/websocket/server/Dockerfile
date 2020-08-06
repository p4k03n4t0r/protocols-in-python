FROM python:3
WORKDIR /usr/src/app
COPY . .
RUN pip3 install flask
ENTRYPOINT [ "tail", "-f", "/dev/null" ]
# ENTRYPOINT ["python3", "-u", "server.py"]