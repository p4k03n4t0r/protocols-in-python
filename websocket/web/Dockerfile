FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY index.js /usr/share/nginx/html/index.js
COPY domain.crt /etc/nginx/cert.crt
COPY domain.key /etc/nginx/cert.key
COPY nginx-default.conf /etc/nginx/conf.d/default.conf