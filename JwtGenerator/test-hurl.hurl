# ==============================================================================
# FLUSSO E2E E TEST DI ROBUSTEZZA (Unhappy Paths)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. FLUSSO FELICE (Happy Path)
# ------------------------------------------------------------------------------
POST {{base_url}}/api/jwt/generate
Content-Type: application/json
{ "id": 1, "roles": ["ADMIN"] }
HTTP 200
[Captures]
access: jsonpath "$.accessToken"
refresh: jsonpath "$.refreshToken"

POST {{base_url}}/api/jwt/introspect
Content-Type: application/json
{ "accessToken": "{{access}}" }
HTTP 200

POST {{base_url}}/api/jwt/refresh
Content-Type: application/json
{ "refreshToken": "{{refresh}}" }
HTTP 200
[Captures]
new_refresh: jsonpath "$.refreshToken"

POST {{base_url}}/api/jwt/logout
Content-Type: application/json
{ "refreshToken": "{{new_refresh}}" }
HTTP 200

# ------------------------------------------------------------------------------
# 2. VALIDAZIONE CAMPI (400 Bad Request)
# ------------------------------------------------------------------------------

# Generate: Body vuoto o mancante
POST {{base_url}}/api/jwt/generate
Content-Type: application/json
{}
HTTP 400

# Generate: ID non numerico
POST {{base_url}}/api/jwt/generate
Content-Type: application/json
{ "id": "non-un-numero", "roles": ["USER"] }
HTTP 400

# ------------------------------------------------------------------------------
# 3. AUTORIZZAZIONE E STATI (401 Unauthorized)
# ------------------------------------------------------------------------------

# Introspect: Token non esistente
POST {{base_url}}/api/jwt/introspect
Content-Type: application/json
{ "accessToken": "token-inesistente" }
HTTP 401

# Refresh: Token già revocato (dopo il logout precedente)
POST {{base_url}}/api/jwt/refresh
Content-Type: application/json
{ "refreshToken": "{{new_refresh}}" }
HTTP 401

# ------------------------------------------------------------------------------
# 4. PROTOCOLLO E METODI (401 & 415)
# ------------------------------------------------------------------------------

# Metodo non permesso (Spring Security blocca con 401 prima di arrivare al controller)
GET {{base_url}}/api/jwt/generate
HTTP 401

# Content-Type errato (Spring Security blocca con 401 per sicurezza prima del 415)
POST {{base_url}}/api/jwt/generate
Content-Type: text/plain
{ "id": 1 }
HTTP 401
