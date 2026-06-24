package producer

func IsAllowedAuthor(login string, allowedAuthors []string) bool {
	for _, allowed := range allowedAuthors {
		if allowed == "*" || allowed == login {
			return true
		}
	}
	return false
}
