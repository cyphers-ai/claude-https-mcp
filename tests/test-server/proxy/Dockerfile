FROM alpine:3.19

RUN apk add --no-cache squid apache2-utils

# Create directories
RUN mkdir -p /var/cache/squid /var/log/squid /var/run/squid

# Copy configuration
COPY squid.conf /etc/squid/squid.conf

# Create password file for authenticated proxy
RUN htpasswd -bc /etc/squid/passwords testuser testpassword

# Set permissions
RUN chown -R squid:squid /var/cache/squid /var/log/squid /var/run/squid

# Initialize cache
RUN squid -z -N 2>/dev/null || true

EXPOSE 3128 3129

CMD ["squid", "-N", "-d", "1"]
