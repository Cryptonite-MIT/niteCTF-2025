#!/bin/bash

mkdir -p /var/log/nginx /var/lib/nginx /var/cache/nginx

echo "127.0.0.1 nite-sso" >> /etc/hosts
echo "127.0.0.1 document-portal" >> /etc/hosts
echo "127.0.0.1 nite-vault" >> /etc/hosts

sed -i "s/nite\.com/${DOMAIN}/g" /etc/nginx/nginx.conf

supervisord -n -c /app/supervisord.conf
