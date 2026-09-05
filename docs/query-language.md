# Event Query Language

The SOCWerk query language supplements form filters with safe, deterministic investigation expressions. It reads normalized scenario events only.

## Comparisons

```text
source = sysmon
user = usr-ops-402
asset = asset-ws-402
event_type != authentication
bytes_out > 104857600
severity = high
attributes.approved_service = false
mitre = T1059.001
```

`=` on a list checks membership, which makes the MITRE example useful. String equality is case-insensitive. Numeric ordering uses `>`, `<`, `>=`, and `<=`.

`user`, `asset`, and `type` are concise aliases for `user_id`, `asset_id`, and `event_type`.

## Text containment

```text
contains(summary, "PowerShell")
contains(domain, "storage")
```

Quote values containing whitespace. Escaped characters inside quoted values are supported.

## Logic and grouping

```text
source = sysmon and severity = high
event_type = dns_query or event_type = http_request
asset_id = asset-ws-402 and (event_type = process_created or event_type = network_connection)
```

`and` binds more tightly than `or`. Parentheses make precedence explicit.

## Safety and limits

The parser accepts only identifiers, values, comparison operators, `contains`, `and`, `or`, and parentheses. Query length is limited to 1,000 characters. The compiled result is an in-memory event predicate.

The language has no SQL, comments, subqueries, filesystem paths, network functions, regular expressions, loops, imports, assignments, or general-purpose evaluation. A malformed expression returns a client error with the approximate location; it cannot alter investigation state.
