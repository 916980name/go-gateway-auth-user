package common

func StringArrayOpt(sa []string, operation func(string) string) {
	for i, v := range sa {
		sa[i] = operation(v)
	}
}
