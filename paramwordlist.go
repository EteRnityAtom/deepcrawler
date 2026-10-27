package main

// Built-in common-parameter wordlist (replaces arjun's own list).
// Direct port of deep_crawler.py's COMMON_PARAM_WORDLIST.
var commonParamWordlist = []string{
	"id", "user", "username", "user_id", "userid", "uid", "account", "account_id",
	"email", "token", "access_token", "api_key", "apikey", "key", "secret",
	"session", "session_id", "sid", "auth", "password", "pass", "pwd",
	"redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnUrl",
	"next", "continue", "url", "target", "dest", "destination", "callback",
	"file", "filename", "path", "filepath", "dir", "folder", "page", "template",
	"include", "load", "view", "doc", "document",
	"cmd", "command", "exec", "query", "q", "search", "filter", "sort", "order",
	"orderby", "limit", "offset", "page_size", "pagesize", "per_page",
	"role", "admin", "is_admin", "isadmin", "permission", "permissions", "level",
	"access", "access_level", "scope", "debug", "test", "dev", "mode",
	"format", "type", "action", "method", "op", "do",
	"name", "title", "comment", "message", "content", "body", "text", "bio",
	"price", "amount", "qty", "quantity", "total", "discount", "coupon", "code",
	"lang", "lang_id", "locale", "country", "currency",
	"from", "to", "start", "end", "date", "timestamp", "time",
	"ref", "referrer", "referer", "source", "src", "utm_source", "campaign",
	"version", "v", "api_version", "client_id", "client_secret", "state", "nonce",
	"otp", "verify", "verification_code", "reset_token", "confirm", "confirmation",
	"active", "enabled", "status", "visible", "public", "private", "hidden",
	"json", "xml", "jsonp", "output", "export", "import", "upload", "download",
}
