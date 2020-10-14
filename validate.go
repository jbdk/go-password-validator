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

	hasSpecial := false
	hasLower := false
	hasUpper := false
	hasDigits := false
	for _, c := range password {
		if containsRune(specialChars, c) {
			hasSpecial = true
			continue
		}
		if containsRune(lowerChars, c) {
			hasLower = true
			continue
		}
		if containsRune(upperChars, c) {
			hasUpper = true
			continue
		}
		if containsRune(digitsChars, c) {
			hasDigits = true
			continue
		}
	}

	allMessages := []string{}

	if !hasSpecial {
		allMessages = append(allMessages, "including special characters")
	}
	if !hasLower {
		allMessages = append(allMessages, "using lowercase letters")
	}
	if !hasUpper {
		allMessages = append(allMessages, "using uppercase letters")
	}
	if !hasDigits {
		allMessages = append(allMessages, "using numbers")
	}

	if len(allMessages) > 0 {
		return fmt.Errorf(
			"Insecure password. Try %v or using a longer password",
			strings.Join(allMessages, ", "),
		)
	}

	return errors.New("Insecure password. Try using a longer password")
}
