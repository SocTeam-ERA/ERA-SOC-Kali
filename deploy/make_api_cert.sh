#!/usr/bin/env bash
# =====================================================================
#  make_api_cert.sh -- the TLS certificate for the Kali API on HTTPS (soc-api-tls.service, port 8443)
# =====================================================================
#  Run once, as root:   sudo bash /opt/sentinel-soc/deploy/make_api_cert.sh
#  Renew (new server certificate, same CA, so the backend needs no change):
#                       sudo bash /opt/sentinel-soc/deploy/make_api_cert.sh --renew
#
#  Creates in /etc/sentinel-soc/tls/:
#    ca.pem    a small private CA, valid 10 years. THIS is the file the platform backend trusts
#              (KALI_API_CA_CERT); it is public, safe to copy.
#    ca.key    its key, root only (600). Needed only to renew api.pem. Never leaves this machine.
#    api.pem   the API's certificate, signed by the CA, valid 825 days, for the names and IPs below.
#    api.key   its key, root:soc 640, read by soc-api-tls.service. Never leaves this machine.
#
#  Why a CA and not one self-signed certificate: renewing api.pem then changes nothing on the backend,
#  and the chain passes Python's strict X.509 checks (VERIFY_X509_STRICT, on by default since 3.13).
#  Keys are secrets and stay out of git (see CLAUDE.md); this script is what reproduces them.
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0 $*"; exit 1; }

DIR=/etc/sentinel-soc/tls
SAN="${SOC_API_CERT_SAN:-DNS:kali2,DNS:kali2.era.local,IP:10.69.0.40,IP:127.0.0.1}"
RENEW=0; [[ "${1:-}" == "--renew" ]] && RENEW=1

install -d -m 750 -o root -g soc "$DIR"
cd "$DIR"

if [[ ! -f ca.key ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout ca.key -out ca.pem -subj "/O=ERA Sentinel SOC/CN=Sentinel SOC Kali API CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
  chmod 600 ca.key; chmod 644 ca.pem
  echo "[1/2] CA created: $DIR/ca.pem"
else
  echo "[1/2] CA already exists: $DIR/ca.pem"
fi

if [[ -f api.pem && $RENEW -eq 0 ]]; then
  echo "[2/2] api.pem already exists (expires $(openssl x509 -in api.pem -noout -enddate | cut -d= -f2)); --renew to replace it"
else
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout api.key.new -out api.csr \
    -subj "/O=ERA Sentinel SOC/CN=kali2.era.local" 2>/dev/null
  openssl x509 -req -in api.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 -out api.pem.new \
    -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" \
                               "keyUsage=critical,digitalSignature" \
                               "extendedKeyUsage=serverAuth" \
                               "subjectKeyIdentifier=hash" \
                               "authorityKeyIdentifier=keyid" \
                               "subjectAltName=$SAN") 2>/dev/null
  mv api.key.new api.key; mv api.pem.new api.pem; rm -f api.csr
  chown root:soc api.key api.pem; chmod 640 api.key; chmod 644 api.pem
  echo "[2/2] api.pem issued for $SAN, expires $(openssl x509 -in api.pem -noout -enddate | cut -d= -f2)"
  [[ $RENEW -eq 1 ]] && echo "      restart it:  systemctl restart soc-api-tls"
fi

openssl verify -CAfile ca.pem api.pem >/dev/null && echo "Chain verified. Give the backend this file (public): $DIR/ca.pem"
