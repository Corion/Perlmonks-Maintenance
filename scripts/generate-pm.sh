#!/bin/bash
PATH=/opt/perl-5.18/bin:$PATH

SSH_VARS=$HOME/.ssh/vars.sh

[ -s $SSH_VARS ] && . $SSH_VARS 2>&1 >> /dev/null

cd $(dirname $0)
LIMIT=21 # renew 21 days before expiration
LIB=~/repos/Crypt-LE-Challenge-External/lib

# perlmonks.org.key is the letsencrypt "account"
# *.csr.key is the certificate key
# *.crt is the certificate

perl -I$LIB -w /opt/perl-5.18/bin/le.pl --issue-code 1 $* --renew $LIMIT --key perlmonks.org.key --email "perlmonks.org@gmail.com" --csr perlmonks.org.csr --csr-key perlmonks.org.csr.key --crt perlmonks.org.crt --domains "perlmonks.org,www.perlmonks.org,css.perlmonks.org,perlmonks.net,www.perlmonks.net,css.perlmonks.net,perlmonks.com,www.perlmonks.com,css.perlmonks.com" --generate-missing --path "well-known/" --handle-with Crypt::LE::Challenge::External --handle-params '{"command":"./upload-challenge-pm.sh echo ${token}.${fingerprint} \\> ./public_html/.well-known/acme-challenge/${token}"}' --quiet --issue-code 2

# mail the certificates to Pair admins

if [[ $? -eq 2 ]]; then
s-nail -s "New Let's Encrypt Certificates for perlmonks.com attached" -a perlmonks.org.crt -a perlmonks.org.csr.key corion-perlmonks@corion.net perlmonks.org@gmail.com <<EOM
Please find attached the new Let's Encrypt Certificates.

Please install them in Apache on these machines

qs1969.pair.com
qs321.pair.com
qs343.pair.com

Thank you very much,
Max (for the perlmonks admins)

--
This mail was generated automatically
EOM
fi
