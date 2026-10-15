# Read stripped Rust first, then its original text. The first input comes from
# strip-rust.awk and keeps line numbers while removing comments and literals.
# Inspect whole attributes so rustfmt's multiline derives remain covered.
BEGIN {
	while ((getline comment_location < line_comments) > 0) {
		split(comment_location, location, " ")
		comments[location[1]] = location[2]
	}
	close(line_comments)
}
NR == FNR { code[FNR] = $0; next }
{
	source = source code[FNR] "\n"
	comment_start = comments[FNR]
	if (comment_start && substr($0, comment_start) ~ /^\/\/[[:space:]]*debug-ok:[[:space:]]*[^[:space:]]/) {
		# Match only at the scanner's actual token, not another // earlier
		# in a literal or block comment sharing this physical line.
		prefix = substr($0, 1, comment_start - 1)
		if (prefix ~ /^[[:space:]]*$/) preceding[FNR] = 1
		if (prefix == code[FNR]) inline_reason[FNR] = 1
	}
}
END {
	line = 1
	for (i = 1; i <= length(source); i++) {
		c = substr(source, i, 1)
		if (c == "\n") { line++; continue }
		if (c != "#") continue
		j = i + 1
		while (substr(source, j, 1) ~ /[[:space:]]/) j++
		if (substr(source, j, 1) != "[") continue
		first_line = line
		depth = 1; attribute = ""
		for (k = j + 1; k <= length(source) && depth; k++) {
			c = substr(source, k, 1)
			if (c == "[") depth++
			if (c == "]") depth--
			attribute = attribute c
		}
		if (attribute !~ /(^|[^[:alnum:]_])derive[[:space:]]*\(/ ||
			attribute !~ /(^|[^[:alnum:]_])Debug([^[:alnum:]_]|$)/) continue
		last_line = first_line
		for (p = i; p < k; p++) if (substr(source, p, 1) == "\n") last_line++
		reason = preceding[first_line - 1]
		for (p = first_line; p <= last_line; p++) reason = reason || inline_reason[p]
		if (!reason) {
			print FILENAME ":" first_line ": derived Debug without a debug-ok reason"
			bad = 1
		}
	}
	exit bad
}
