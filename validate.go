package passwordvalidator

import (
	"errors"
	"fmt"
	"strings"
)

// Validate returns nil if the password has greater than or
// equal to the minimum entropy. If not, an error is returned
// that explains how the password can be strengthened. This error
// is safe to show the client
func Validate(password string, minEntropy float64) error {
	entropy := getEntropy(password)
	if entropy >= minEntropy {
		return nil
	}

	hasReplace := false
	hasSep := false
	hasOtherSpecial := false
	hasLower := false
	hasUpper := false
	hasDigits := false
	for _, c := range password {
		if strings.ContainsRune(replaceChars, c) {
			hasReplace = true
			continue
		}
		if strings.ContainsRune(sepChars, c) {
			hasSep = true
			continue
		}
		if strings.ContainsRune(otherSpecialChars, c) {
			hasOtherSpecial = true
			continue
		}
		if strings.ContainsRune(lowerChars, c) {
			hasLower = true
			continue
		}
		if strings.ContainsRune(upperChars, c) {
			hasUpper = true
			continue
		}
		if strings.ContainsRune(digitsChars, c) {
			hasDigits = true
			continue
		}
	}

	allMessages := []string{}

	if !hasOtherSpecial || !hasSep || !hasReplace {
		allMessages = append(allMessages, "brug flere specialtegn")
	}
	if !hasLower {
		allMessages = append(allMessages, "ved hjælp af små bogstaver")
	}
	if !hasUpper {
		allMessages = append(allMessages, "ved hjælp af store bogstaver")
	}
	if !hasDigits {
		allMessages = append(allMessages, "ved hjælp af tal")
	}

	if len(allMessages) > 0 {
		return fmt.Errorf(
			"usikker adgangskode, prøv %v eller brug en længere adgangskode",
			strings.Join(allMessages, ", "),
		)
	}

	return errors.New("usikker adgangskode, prøv at bruge en længere adgangskode")
}
