# Append to grantor-api; this fragment does not replace its existing policy.
path "grantor/data/accounts/+/verification-proofs/+" {
  capabilities = ["create", "read"]
}
path "grantor/metadata/accounts/+/verification-proofs/+" {
  capabilities = ["delete"]
}
