# Append to grantor-worker; this fragment does not replace its existing policy.
path "grantor/data/accounts/+/verification-proofs/+" {
  capabilities = ["read"]
}
path "grantor/metadata/accounts/+/verification-proofs/+" {
  capabilities = ["delete"]
}
