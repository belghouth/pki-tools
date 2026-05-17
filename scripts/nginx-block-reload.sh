#!/bin/bash
# nginx-block-reload — wrapper called by www-data via sudo to reload nginx safely
# Deploy to: /usr/local/sbin/nginx-block-reload  (root:root, chmod 755)
# Sudoers:   www-data ALL=(root) NOPASSWD: /usr/local/sbin/nginx-block-reload
set -e
nginx -t
systemctl reload nginx
