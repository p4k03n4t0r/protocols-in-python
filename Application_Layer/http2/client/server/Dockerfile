FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY domain.crt /etc/nginx/cert.crt
COPY domain.key /etc/nginx/cert.key
COPY nginx-default.conf /etc/nginx/conf.d/default.conf