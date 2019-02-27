#!/bin/sh
# https://www.ory.sh/run-oauth2-server-open-source-api-security

set -eux

docker rm -f hydra hydra-consent || true
docker network rf -f hydra || true

docker network create hydra

HYDRA=oryd/hydra:v1.0.0-rc.6_oryOS.10-alpine
docker run -d --name hydra --network hydra -p 4444:4444 -p 4445:4445 \
  -e DATABASE_URL=memory -e SYSTEM_SECRET=hydra-system-secret \
  -e OAUTH2_ISSUER_URL=http://127.0.0.1:4444/ \
  -e OAUTH2_CONSENT_URL=http://127.0.0.1:3000/consent \
  -e OAUTH2_LOGIN_URL=http://127.0.0.1:3000/login \
  $HYDRA serve all --dangerous-force-http

until curl -f http://localhost:4445/health/ready; do
  sleep 1;
done

docker run --network hydra -it --rm $HYDRA clients create \
  --endpoint http://hydra:4445 --id CLIENT_ID --secret CLIENT_SECRET \
  --grant-types authorization_code,refresh_token \
  --response-types token,code,id_token \
  --scope openid --callbacks http://localhost:4080/oauth/callback/hydra

docker run -d --name hydra-consent --network hydra -p 3000:3000 \
  -e HYDRA_URL=http://hydra:4445 -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  oryd/hydra-login-consent-node:v1.0.0-rc.6

until curl -sf localhost:3000 > /dev/null; do
  sleep 1;
done
