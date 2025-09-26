/// Opaque rule identifier.
///
/// A newtype over `u32` so the compiler distinguishes rule IDs from
/// structurally identical integers (ports, thresholds, counts). The
/// distinction is purely static; the representation is the same `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct RuleId(pub u32);

impl RuleId {
    /// Zero is the sentinel for "no rule"; valid IDs start at 1.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The three terminal actions a rule can produce.
///
/// Serde deserialises this from TOML strings, so an unrecognised action
/// is a parse error, not a runtime surprise.  Aliases (`reject`, `block`
/// for `Drop`, etc.) exist for backward compatibility with rule files
/// written against earlier naming conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Audit-log the match; forward normally.
    #[serde(alias = "allow", alias = "allow_and_log")]
    Log,
    /// Reroute to the forward-target backend (honeypot, tarpit, etc.).
    #[serde(alias = "send_to_honeypot")]
    Forward,
    /// Terminate with 403.  The request never reaches any backend.
    #[serde(alias = "reject", alias = "block")]
    Drop,
}

impl Action {
    /// Total order for conflict resolution when multiple rules fire.
    /// Drop > Forward > Log.
    pub fn precedence_rank(self) -> u8 {
        match self {
            Self::Drop => 3,
            Self::Forward => 2,
            Self::Log => 1,
        }
    }

    /// Canonical string form, used in the `x-aegira-action` header and logs.
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Forward => "forward",
            Self::Drop => "drop",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_header_value())
    }
}

/// Inspection surface of a rule: which segment of the HTTP exchange
/// the regex is matched against.
///
/// Parsed from the `when` array in TOML.  Unrecognised values fail the
/// parse, so the set of valid targets is closed at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Path,
    #[serde(alias = "query")]
    QueryString,
    /// All request header values, concatenated.  Alias: `headers`.
    #[serde(alias = "headers")]
    RequestHeaders,
    /// UTF-8 request body text.  Alias: `body`.
    #[serde(alias = "body")]
    RequestBody,
    /// Individual cookie name=value pairs (RFC 6265).  Alias: `cookie`.
    #[serde(alias = "cookie")]
    Cookies,
    ResponseHeaders,
    ResponseBody,
}

impl Target {
    pub fn is_response(self) -> bool {
        matches!(self, Self::ResponseHeaders | Self::ResponseBody)
    }
}

/// Canonicalised HTTP request presented to the rule engine.
///
/// All decoding (percent, HTML entities, NFKC) is applied once during
/// construction.  Rules never see raw wire bytes.
#[derive(Debug, Clone, Default)]
pub struct NormalizedRequest {
    pub host: String,
    pub path: String,
    pub query_string: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: String,
}

impl NormalizedRequest {
    pub fn header_blob(&self) -> String {
        self.headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn cookie_blob(&self) -> String {
        self.cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Canonicalised HTTP response for rules targeting response fields.
#[derive(Debug, Clone, Default)]
pub struct NormalizedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl NormalizedResponse {
    pub fn header_blob(&self) -> String {
        self.headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
