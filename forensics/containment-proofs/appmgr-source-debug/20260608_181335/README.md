# AppMgr Source Debug

Goal:
Find why POST /ric/v1/xapps returns 501 Not Implemented.

Hypothesis:
The OpenAPI route exists, but the generated Go server handler for deployXapp is not wired to an implementation.
