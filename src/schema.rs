// Schema enforcement: validate request bodies against an OpenAPI specification
// before the regex engine runs.  A valid JSON structure that satisfies the
// schema is allowed through; anything else is rejected at the gate.  This is
// the "positive security model" layer -- instead of pattern-matching known
// attacks, it rejects anything that does not conform to the declared contract.
//
// Design: Strategy Pattern.  The SchemaValidator trait allows swapping
// implementations (JSON Schema today, potentially XML or Protobuf later)
// without changing the pipeline integration in runtime.rs.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::config::SchemaEnforcement;

// -----------------------------------------------------------------------
// Trait: SchemaValidator (Strategy Pattern)
// -----------------------------------------------------------------------

/// Outcome of validating a request body against a schema.
#[derive(Debug)]
pub enum ValidationOutcome {
    /// Body conforms to the schema.
    Valid,
    /// Body violates the schema.  The string describes the first violation.
    Invalid(String),
    /// No schema is registered for this method + path combination.
    /// The request passes through to the regex engine as usual.
    NoSchema,
    /// The method + path is not declared in the OpenAPI spec at all.
    /// Only returned when `reject_unknown_endpoints` is true.
    UnknownEndpoint,
}

/// Strategy interface for body validation against a schema.
///
/// Implementations hold pre-compiled schemas and match incoming requests
/// by HTTP method and path.  The trait exists so the runtime does not
/// depend on jsonschema directly; a future XML Schema or Protobuf
/// descriptor validator can implement the same interface.
pub trait SchemaValidator: Send + Sync {
    /// Validate `body` for the given `method` and `path`.
    ///
    /// Returns `NoSchema` when the spec defines no request body for this
    /// endpoint.  Returns `Invalid` with a human-readable reason on the
    /// first schema violation.
    fn validate(&self, method: &str, path: &str, body: &[u8]) -> ValidationOutcome;
}

// -----------------------------------------------------------------------
// JSON Schema implementation backed by the `jsonschema` crate.
// -----------------------------------------------------------------------

/// A single compiled schema keyed by (METHOD, path_template).
struct CompiledEndpoint {
    method: String,
    /// Original OpenAPI path template, e.g. "/users/{id}".
    path_template: String,
    /// Segments of the path template split on '/'.  Segments starting
    /// with '{' are treated as wildcards during matching.
    segments: Vec<PathSegment>,
    /// `Some` when the operation declares a JSON request body schema.
    /// `None` for operations without a requestBody (GET, DELETE, etc.).
    validator: Option<jsonschema::Validator>,
}

#[derive(Debug, Clone)]
enum PathSegment {
    Literal(String),
    Wildcard,
}

pub struct JsonSchemaValidator {
    endpoints: Vec<CompiledEndpoint>,
    max_body_bytes: usize,
    max_depth: usize,
    /// When true, requests to method+path combinations not declared in
    /// the spec are rejected with `UnknownEndpoint` instead of returning
    /// `NoSchema`.  This makes the spec the single source of truth for
    /// which endpoints exist.
    reject_unknown_endpoints: bool,
}

impl std::fmt::Debug for JsonSchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonSchemaValidator")
            .field("endpoint_count", &self.endpoints.len())
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_depth", &self.max_depth)
            .field("reject_unknown_endpoints", &self.reject_unknown_endpoints)
            .finish()
    }
}

impl JsonSchemaValidator {
    /// Load an OpenAPI 3.x spec from `path`, extract request body schemas
    /// for every operation that declares `application/json` content, and
    /// compile each into a jsonschema::Validator.
    ///
    /// File permission check: on Unix the spec file must not be
    /// world-writable (mode & 0o002 == 0).  A world-writable spec file
    /// means any local user can alter the validation contract.
    pub fn from_openapi(config: &SchemaEnforcement) -> Result<Self> {
        let spec_path = config
            .openapi_spec_path
            .as_deref()
            .context("schema_enforcement.openapi_spec_path is required when enabled")?;

        check_file_permissions(spec_path)?;

        let raw = std::fs::read_to_string(spec_path)
            .with_context(|| format!("read OpenAPI spec {spec_path}"))?;

        let max_body_bytes = config.max_body_bytes.unwrap_or(1_048_576);
        let max_depth = config.max_depth.unwrap_or(64);
        let reject_unknown_endpoints = config.reject_unknown_endpoints.unwrap_or(false);

        let doc: Value = if spec_path.ends_with(".yaml") || spec_path.ends_with(".yml") {
            bail!("YAML OpenAPI specs are not supported; convert to JSON first");
        } else {
            serde_json::from_str(&raw)
                .with_context(|| format!("parse OpenAPI spec as JSON: {spec_path}"))?
        };

        // Verify it looks like an OpenAPI 3.x document.
        let version = doc
            .get("openapi")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !version.starts_with("3.") {
            bail!(
                "unsupported OpenAPI version \"{version}\"; only 3.x is supported"
            );
        }

        let paths = doc
            .get("paths")
            .and_then(|v| v.as_object())
            .context("OpenAPI spec is missing a \"paths\" object")?;

        // Inline $ref resolution: collect top-level component schemas
        // so we can substitute them before compiling.
        let components = doc.get("components").cloned().unwrap_or(Value::Null);

        let mut endpoints = Vec::new();

        for (path_template, path_item) in paths {
            let path_obj = match path_item.as_object() {
                Some(obj) => obj,
                None => continue,
            };

            let segments = parse_path_template(path_template);

            for (method, operation) in path_obj {
                // Skip non-operation keys like "parameters", "summary".
                let http_methods = [
                    "get", "post", "put", "patch", "delete", "head", "options", "trace",
                ];
                if !http_methods.contains(&method.to_ascii_lowercase().as_str()) {
                    continue;
                }

                let op = match operation.as_object() {
                    Some(obj) => obj,
                    None => continue,
                };

                // Extract requestBody -> content -> application/json -> schema.
                // Operations without a requestBody (GET, DELETE, etc.) are
                // still registered with validator = None so the endpoint
                // inventory is complete.
                let validator = match extract_request_body_schema(op, &components) {
                    Some(schema_value) => {
                        let resolved = resolve_refs(&schema_value, &doc);
                        let v = jsonschema::validator_for(&resolved)
                            .with_context(|| {
                                format!(
                                    "compile JSON Schema for {method} {path_template}"
                                )
                            })?;
                        Some(v)
                    }
                    None => None,
                };

                endpoints.push(CompiledEndpoint {
                    method: method.to_ascii_uppercase(),
                    path_template: path_template.clone(),
                    segments: segments.clone(),
                    validator,
                });
            }
        }

        Ok(Self {
            endpoints,
            max_body_bytes,
            max_depth,
            reject_unknown_endpoints,
        })
    }
}

impl SchemaValidator for JsonSchemaValidator {
    fn validate(&self, method: &str, path: &str, body: &[u8]) -> ValidationOutcome {
        let upper_method = method.to_ascii_uppercase();
        let request_segments: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .collect();

        // Find the first endpoint whose method and path pattern match.
        let endpoint = self.endpoints.iter().find(|ep| {
            ep.method == upper_method && path_matches(&ep.segments, &request_segments)
        });

        let endpoint = match endpoint {
            Some(ep) => ep,
            None => {
                return if self.reject_unknown_endpoints {
                    ValidationOutcome::UnknownEndpoint
                } else {
                    ValidationOutcome::NoSchema
                };
            }
        };

        // Endpoint is in the spec.  If it has no body schema, or the
        // request body is empty, there is nothing to validate.
        let validator = match &endpoint.validator {
            Some(v) => v,
            None => return ValidationOutcome::NoSchema,
        };

        if body.is_empty() {
            return ValidationOutcome::NoSchema;
        }

        // Size gate: reject before parsing.
        if body.len() > self.max_body_bytes {
            return ValidationOutcome::Invalid(format!(
                "request body exceeds schema enforcement limit ({} bytes > {} max)",
                body.len(),
                self.max_body_bytes,
            ));
        }

        // Parse the body as JSON.  Malformed input is a validation failure,
        // not an internal error.
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                return ValidationOutcome::Invalid(
                    "request body is not valid UTF-8".into(),
                );
            }
        };

        let parsed: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                return ValidationOutcome::Invalid(format!(
                    "request body is not valid JSON: {e}"
                ));
            }
        };

        // Depth check: prevent stack exhaustion from deeply nested structures.
        if json_depth(&parsed) > self.max_depth {
            return ValidationOutcome::Invalid(format!(
                "JSON nesting depth exceeds limit (max {})",
                self.max_depth,
            ));
        }

        // Run the compiled validator.
        match validator.validate(&parsed) {
            Ok(()) => ValidationOutcome::Valid,
            Err(error) => ValidationOutcome::Invalid(format!(
                "schema violation at {}: {}",
                endpoint.path_template,
                error,
            )),
        }
    }
}

// -----------------------------------------------------------------------
// Path template parsing and matching.
// -----------------------------------------------------------------------

fn parse_path_template(template: &str) -> Vec<PathSegment> {
    template
        .trim_start_matches('/')
        .split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                PathSegment::Wildcard
            } else {
                PathSegment::Literal(seg.to_ascii_lowercase())
            }
        })
        .collect()
}

fn path_matches(template_segments: &[PathSegment], request_segments: &[&str]) -> bool {
    if template_segments.len() != request_segments.len() {
        return false;
    }
    template_segments
        .iter()
        .zip(request_segments.iter())
        .all(|(tmpl, req)| match tmpl {
            PathSegment::Wildcard => true,
            PathSegment::Literal(lit) => lit == &req.to_ascii_lowercase(),
        })
}

// -----------------------------------------------------------------------
// JSON depth measurement (iterative to avoid stack overflow on input).
// -----------------------------------------------------------------------

fn json_depth(value: &Value) -> usize {
    // Iterative BFS to measure maximum nesting depth.
    let mut max_depth = 0usize;
    let mut stack: Vec<(&Value, usize)> = vec![(value, 1)];

    while let Some((v, depth)) = stack.pop() {
        if depth > max_depth {
            max_depth = depth;
        }
        match v {
            Value::Array(arr) => {
                for item in arr {
                    stack.push((item, depth + 1));
                }
            }
            Value::Object(map) => {
                for (_k, val) in map {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }

    max_depth
}

// -----------------------------------------------------------------------
// OpenAPI helpers: extract request body schemas and resolve $ref.
// -----------------------------------------------------------------------

/// Walk the operation object to find the JSON Schema for an
/// `application/json` request body.  Handles both inline schemas
/// and top-level `$ref` on the requestBody itself.
fn extract_request_body_schema(
    operation: &serde_json::Map<String, Value>,
    components: &Value,
) -> Option<Value> {
    let request_body = operation.get("requestBody")?;

    // The requestBody itself may be a $ref.
    let resolved_body = if let Some(ref_str) = request_body.get("$ref").and_then(|v| v.as_str()) {
        resolve_component_ref(ref_str, components)?
    } else {
        request_body.clone()
    };

    let content = resolved_body.get("content")?.as_object()?;

    // Try exact match first, then any JSON-compatible media type.
    let json_content = content
        .get("application/json")
        .or_else(|| {
            content
                .iter()
                .find(|(k, _)| k.contains("json"))
                .map(|(_, v)| v)
        })?;

    json_content.get("schema").cloned()
}

/// Resolve a `$ref` string like `#/components/schemas/User` against
/// the components object.  Only local (same-document) refs are supported.
fn resolve_component_ref(ref_str: &str, components: &Value) -> Option<Value> {
    if !ref_str.starts_with("#/") {
        return None;
    }
    let pointer = ref_str.trim_start_matches('#');
    components
        .pointer(pointer)
        .or_else(|| {
            // The pointer is relative to the root document, but we received
            // just the "components" subtree.  Try stripping the
            // "/components" prefix.
            let stripped = pointer.strip_prefix("/components")?;
            components.pointer(stripped)
        })
        .cloned()
}

/// Recursively resolve `$ref` pointers within a JSON value.
/// Uses the full OpenAPI document as the resolution root.
/// Tracks seen refs to break circular references.
fn resolve_refs(value: &Value, root: &Value) -> Value {
    resolve_refs_inner(value, root, &mut Vec::new(), 0)
}

fn resolve_refs_inner(
    value: &Value,
    root: &Value,
    seen: &mut Vec<String>,
    depth: usize,
) -> Value {
    // Guard against runaway resolution (Billion Laughs style).
    if depth > 128 {
        return value.clone();
    }

    match value {
        Value::Object(map) => {
            // If this object is a $ref, resolve it.
            if let Some(ref_str) = map.get("$ref").and_then(|v| v.as_str()) {
                if seen.contains(&ref_str.to_string()) {
                    // Circular ref: return the raw $ref object to avoid
                    // infinite expansion.
                    return value.clone();
                }
                if let Some(resolved) = ref_str
                    .strip_prefix('#')
                    .and_then(|pointer| root.pointer(pointer))
                {
                    seen.push(ref_str.to_string());
                    let result = resolve_refs_inner(resolved, root, seen, depth + 1);
                    seen.pop();
                    return result;
                }
                return value.clone();
            }

            // Otherwise recurse into each field.
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.clone(), resolve_refs_inner(v, root, seen, depth + 1));
            }
            Value::Object(out)
        }
        Value::Array(arr) => {
            Value::Array(
                arr.iter()
                    .map(|v| resolve_refs_inner(v, root, seen, depth + 1))
                    .collect(),
            )
        }
        _ => value.clone(),
    }
}

// -----------------------------------------------------------------------
// POSIX file permission check.
// -----------------------------------------------------------------------

/// Reject world-writable spec files.  A spec file writable by any user
/// lets an unprivileged attacker redefine the validation contract.
#[cfg(unix)]
fn check_file_permissions(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat OpenAPI spec file {path}"))?;
    let mode = metadata.permissions().mode();
    if mode & 0o002 != 0 {
        bail!(
            "OpenAPI spec file {path} is world-writable (mode {mode:04o}); \
             fix permissions before enabling schema enforcement"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_file_permissions(_path: &str) -> Result<()> {
    Ok(())
}

// -----------------------------------------------------------------------
// Registry: holds the active validator and provides a clean lookup API
// for the runtime pipeline.
// -----------------------------------------------------------------------

/// Holds a compiled SchemaValidator and exposes a method the runtime
/// calls on each request.  When schema enforcement is disabled, the
/// registry is `None` and the pipeline skips validation entirely.
pub struct SchemaRegistry {
    validator: Box<dyn SchemaValidator>,
}

impl SchemaRegistry {
    pub fn new(validator: Box<dyn SchemaValidator>) -> Self {
        Self { validator }
    }

    pub fn validate(&self, method: &str, path: &str, body: &[u8]) -> ValidationOutcome {
        self.validator.validate(method, path, body)
    }
}

/// Build a SchemaRegistry from config.  Returns `None` when schema
/// enforcement is disabled or unconfigured, `Some(registry)` when a
/// spec is loaded and compiled, and `Err` when the config is enabled
/// but the spec cannot be loaded.
pub fn build_registry(config: &SchemaEnforcement) -> Result<Option<SchemaRegistry>> {
    if !config.enabled {
        return Ok(None);
    }

    let validator = JsonSchemaValidator::from_openapi(config)?;
    Ok(Some(SchemaRegistry::new(Box::new(validator))))
}


// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    fn write_spec(spec_json: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create temp file");
        f.write_all(spec_json.as_bytes()).expect("write spec");
        f.flush().expect("flush");
        f
    }

    fn minimal_openapi_spec() -> String {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/users": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    },
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "email"],
                                        "properties": {
                                            "name": { "type": "string", "maxLength": 128 },
                                            "email": { "type": "string", "format": "email" },
                                            "age": { "type": "integer", "minimum": 0, "maximum": 200 }
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        },
                        "responses": { "201": { "description": "created" } }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    },
                    "put": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" }
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    },
                    "delete": {
                        "responses": { "204": { "description": "deleted" } }
                    }
                }
            }
        })
        .to_string()
    }

    fn make_config(spec_path: &str) -> SchemaEnforcement {
        SchemaEnforcement {
            enabled: true,
            openapi_spec_path: Some(spec_path.into()),
            max_body_bytes: Some(65_536),
            max_depth: Some(32),
            reject_unknown_endpoints: None,
        }
    }

    #[test]
    fn valid_body_passes() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":"Alice","email":"alice@example.com"}"#;
        match validator.validate("POST", "/users", body) {
            ValidationOutcome::Valid => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn missing_required_field_fails() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":"Alice"}"#;
        match validator.validate("POST", "/users", body) {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("schema violation"), "unexpected message: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn extra_field_rejected_by_additional_properties_false() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":"Alice","email":"a@b.com","admin":true}"#;
        match validator.validate("POST", "/users", body) {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("schema violation"), "unexpected message: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_type_fails() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":123,"email":"a@b.com"}"#;
        match validator.validate("POST", "/users", body) {
            ValidationOutcome::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn path_parameter_wildcard_matches() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":"Bob"}"#;
        match validator.validate("PUT", "/users/42", body) {
            ValidationOutcome::Valid => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn unregistered_endpoint_returns_no_schema() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        // PATCH /users/42 is not in the spec, so it is unregistered.
        match validator.validate("PATCH", "/users/42", b"") {
            ValidationOutcome::NoSchema => {}
            other => panic!("expected NoSchema, got {other:?}"),
        }
    }

    #[test]
    fn known_endpoint_without_body_returns_no_schema() {
        // GET /users is in the spec but has no requestBody.
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        match validator.validate("GET", "/users", b"") {
            ValidationOutcome::NoSchema => {}
            other => panic!("expected NoSchema for bodyless GET, got {other:?}"),
        }
    }

    #[test]
    fn delete_endpoint_registered_without_body() {
        // DELETE /users/{id} is in the spec without a requestBody.
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        match validator.validate("DELETE", "/users/99", b"") {
            ValidationOutcome::NoSchema => {}
            other => panic!("expected NoSchema for DELETE, got {other:?}"),
        }
    }

    #[test]
    fn reject_unknown_endpoints_blocks_unlisted_path() {
        let spec = write_spec(&minimal_openapi_spec());
        let mut config = make_config(spec.path().to_str().unwrap());
        config.reject_unknown_endpoints = Some(true);
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        // /admin is not in the spec.
        match validator.validate("GET", "/admin", b"") {
            ValidationOutcome::UnknownEndpoint => {}
            other => panic!("expected UnknownEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn reject_unknown_endpoints_allows_listed_path() {
        let spec = write_spec(&minimal_openapi_spec());
        let mut config = make_config(spec.path().to_str().unwrap());
        config.reject_unknown_endpoints = Some(true);
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        // GET /users is in the spec.
        match validator.validate("GET", "/users", b"") {
            ValidationOutcome::NoSchema => {}
            other => panic!("expected NoSchema for known GET, got {other:?}"),
        }
    }

    #[test]
    fn reject_unknown_endpoints_still_validates_body() {
        let spec = write_spec(&minimal_openapi_spec());
        let mut config = make_config(spec.path().to_str().unwrap());
        config.reject_unknown_endpoints = Some(true);
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let body = br#"{"name":"Alice","email":"a@b.com"}"#;
        match validator.validate("POST", "/users", body) {
            ValidationOutcome::Valid => {}
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_fails() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        match validator.validate("POST", "/users", b"{not json}") {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("not valid JSON"), "unexpected: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn invalid_utf8_fails() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        match validator.validate("POST", "/users", &[0xFF, 0xFE, 0x00]) {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("UTF-8"), "unexpected: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn body_exceeding_max_bytes_fails() {
        let spec = write_spec(&minimal_openapi_spec());
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        let large = vec![b'x'; 100_000];
        match validator.validate("POST", "/users", &large) {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("exceeds"), "unexpected: {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn deeply_nested_json_rejected() {
        let spec = write_spec(&minimal_openapi_spec());
        let mut config = make_config(spec.path().to_str().unwrap());
        config.max_depth = Some(4);
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");
        // Build JSON nesting beyond the limit.
        let mut nested = String::from(r#"{"name":"x","email":"a@b.com","age":"#);
        for _ in 0..10 {
            nested.push_str("[{\"a\":");
        }
        nested.push('1');
        for _ in 0..10 {
            nested.push_str("}]");
        }
        nested.push('}');
        // This body won't match the schema either, but the depth check
        // should fire first.
        match validator.validate("POST", "/users", nested.as_bytes()) {
            ValidationOutcome::Invalid(msg) => {
                assert!(msg.contains("depth"), "expected depth error, got: {msg}");
            }
            other => panic!("expected Invalid for deep nesting, got {other:?}"),
        }
    }

    #[test]
    fn json_depth_measurement() {
        // Flat object: outer object (1) + scalar value (2) = depth 2.
        let flat: Value = serde_json::json!({"a": 1});
        assert_eq!(json_depth(&flat), 2);

        let nested: Value = serde_json::json!({"a": {"b": {"c": 1}}});
        assert_eq!(json_depth(&nested), 4);

        let array: Value = serde_json::json!([[[1]]]);
        assert_eq!(json_depth(&array), 4);

        let scalar: Value = serde_json::json!(42);
        assert_eq!(json_depth(&scalar), 1);
    }

    #[test]
    fn ref_resolution_works() {
        let spec_json = serde_json::json!({
            "openapi": "3.0.3",
            "info": { "title": "Test", "version": "1.0" },
            "components": {
                "schemas": {
                    "Item": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": { "type": "integer" }
                        },
                        "additionalProperties": false
                    }
                }
            },
            "paths": {
                "/items": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Item" }
                                }
                            }
                        },
                        "responses": { "201": { "description": "created" } }
                    }
                }
            }
        })
        .to_string();

        let spec = write_spec(&spec_json);
        let config = make_config(spec.path().to_str().unwrap());
        let validator = JsonSchemaValidator::from_openapi(&config).expect("load spec");

        // Valid body.
        match validator.validate("POST", "/items", br#"{"id":1}"#) {
            ValidationOutcome::Valid => {}
            other => panic!("expected Valid, got {other:?}"),
        }

        // Invalid: extra field.
        match validator.validate("POST", "/items", br#"{"id":1,"extra":"x"}"#) {
            ValidationOutcome::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_spec_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let spec = write_spec(&minimal_openapi_spec());
        let path = spec.path();

        // Make it world-writable.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
            .expect("set permissions");

        let config = make_config(path.to_str().unwrap());
        let err = JsonSchemaValidator::from_openapi(&config).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("world-writable"),
            "expected permission error, got: {msg}"
        );
    }

    #[test]
    fn disabled_config_returns_none() {
        let config = SchemaEnforcement {
            enabled: false,
            openapi_spec_path: None,
            max_body_bytes: None,
            max_depth: None,
            reject_unknown_endpoints: None,
        };
        let result = build_registry(&config).expect("build_registry should succeed");
        assert!(result.is_none());
    }
}
