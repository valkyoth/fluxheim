# ACME incident target qualification

The companion selects revocation and doctor targets from managed vhosts, not
the renewal queue. Unknown names and disabled ACME scopes remain ineligible.
Renewal commands continue to use the renewal queue, including forced orders.

The Pebble fixture issues and activates a known leaf, then revokes with a
detached companion using a renewal-disabled configuration. The fixture compares
the fingerprint in the CA-confirmed revocation with the installed leaf,
checks quarantine filenames and verifies no new order appeared. A real TLS
connection proves the isolated gateway can still serve its in-memory leaf:
an operator must not use a successful remote revocation as proof of activation.

Run `python3 scripts/test_acme_scope_smoke.py` and `sh scripts/check_acme_scope.sh`.
