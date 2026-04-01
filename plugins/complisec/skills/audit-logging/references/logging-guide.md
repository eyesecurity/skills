# Audit Logging — Code Generation Guide

## Mandatory operations to log

| Operation | What to log | Severity |
|-----------|------------|----------|
| **Authentication** | Login attempts, failures, token refresh, session creation/destruction | HIGH (failures), INFO (success) |
| **Authorization** | Access granted/denied, role checks, permission evaluation | HIGH (denied), INFO (granted) |
| **Data access** | Read/write/delete of personal or sensitive data | MEDIUM (read), HIGH (write/delete) |
| **Data modification** | Create, update, delete of any business entity | MEDIUM |
| **External API calls** | Outbound requests to third-party services | INFO |
| **Errors** | Exceptions, unexpected states, failed validations | HIGH (security), MEDIUM (business) |
| **Config changes** | Settings modified, feature flags toggled | HIGH |
| **Batch jobs** | Job start, completion, failure, items processed | INFO (start/end), HIGH (failure) |

## Format: structured, not string interpolation

```python
# CORRECT
logger.info("order_created", extra={"order_id": order.id, "customer_id": order.customer_id})

# WRONG
logger.info(f"Created order {order.id} for customer {order.customer_id}")
```

```javascript
// CORRECT
logger.info({ event: "order_created", orderId: order.id, customerId: order.customerId });

// WRONG
logger.info(`Created order ${order.id} for customer ${order.customerId}`);
```

```go
// CORRECT
slog.Info("order_created", "order_id", order.ID, "customer_id", order.CustomerID)

// WRONG
log.Printf("Created order %s for customer %s", order.ID, order.CustomerID)
```

## What MUST NOT be logged

| Never log | Why | Log instead |
|-----------|-----|-------------|
| Passwords / credentials | Credential exposure | `"auth_method": "password"` |
| Full credit card numbers | PCI DSS | `"card_last4": "4242"` |
| National IDs (BSN, SSN) | GDPR Art. 87 | `"has_bsn": true` |
| Session tokens / JWTs | Session hijack | `"session_prefix": "abc..."` |
| PII in request bodies | GDPR minimisation | Field names only |
| Health/biometric data | GDPR Art. 9 | `"data_category": "health"` |

## Language-specific loggers

| Language | Logger | Format |
|----------|--------|--------|
| Python | `structlog` or stdlib `logging` + JSON | `logger.info("event", key=value)` |
| JS/TS | `pino` or `winston` + JSON | `logger.info({ event, key })` |
| Go | `log/slog` (1.21+) or `zap` | `slog.Info("event", "key", value)` |
| Java | `SLF4J` + `logback` + JSON | `logger.info("event", kv("key", value))` |
| Rust | `tracing` + JSON subscriber | `info!(event = "name", key = value)` |
| C# | `Serilog` + JSON sink | `Log.Information("Event {Key}", value)` |

## Correlation

Include when available: `trace_id`, `request_id`, `user_id` (never PII, just the ID).
