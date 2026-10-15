# Prints Rust source with comments, string literals and character
# literals removed (newlines kept), so a search for a keyword sees only
# code. Handles line and nested block comments, "..." with escapes,
# raw strings r#"..."# (also br and cr), and 'c' / '\n' character
# literals versus lifetimes. Used by ci/gates.sh; tested by
# ci/gate-selftest.sh.
BEGIN { st = "code"; depth = 0; hashes = 0 }
{
	line = $0; n = length(line); out = ""; i = 1
	if (st == "line") st = "code"
	while (i <= n) {
		c = substr(line, i, 1); d = substr(line, i + 1, 1)
		if (st == "code") {
			if (c == "/" && d == "/") {
				# Optional line/column output identifies the actual // token;
				# an earlier literal marker on this line is not that comment.
				if (line_comments != "") print FNR, i > line_comments
				st = "line"; break
			}
			if (c == "/" && d == "*") { st = "block"; depth = 1; i += 2; continue }
			# r"..." raw string, br"..." raw byte string, cr"..." raw C string:
			# the prefix starts a token, so the octet before it is not part
			# of an identifier.
			p = (i > 1) ? substr(line, i - 1, 1) : ""
			if (p == "b" || p == "c") p = (i > 2) ? substr(line, i - 2, 1) : ""
			if (c == "r" && (d == "\"" || d == "#") && p !~ /[A-Za-z0-9_]/) {
				j = i + 1; h = 0
				while (substr(line, j, 1) == "#") { h++; j++ }
				if (substr(line, j, 1) == "\"") { st = "raw"; hashes = h; i = j + 1; out = out " "; continue }
			}
			if (c == "\"") { st = "str"; i++; out = out " "; continue }
			if (c == "'") {
				if (d == "\\") { j = i + 2; while (j <= n && substr(line, j, 1) != "'") j++; i = j + 1; out = out " "; continue }
				if (substr(line, i + 2, 1) == "'") { i += 3; out = out " "; continue }
			}
			out = out c; i++; continue
		}
		if (st == "block") {
			if (c == "/" && d == "*") { depth++; i += 2; continue }
			if (c == "*" && d == "/") { depth--; i += 2; if (depth == 0) st = "code"; continue }
			i++; continue
		}
		if (st == "str") {
			if (c == "\\") { i += 2; continue }
			if (c == "\"") { st = "code"; i++; continue }
			i++; continue
		}
		if (st == "raw") {
			if (c == "\"") {
				ok = 1
				for (k = 1; k <= hashes; k++) if (substr(line, i + k, 1) != "#") ok = 0
				if (ok) { st = "code"; i += 1 + hashes; continue }
			}
			i++; continue
		}
		i++
	}
	print out
}
