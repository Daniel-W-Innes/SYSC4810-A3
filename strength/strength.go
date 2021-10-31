package strength

import (
	"bufio"
	"errors"
	"log"
	"os"
	"regexp"
	"unicode"
)

// PasswordPolicy Class for checking passwords against predefined password policy
type PasswordPolicy struct {
	SubPolices  []SubPolicy
	TempPolices []SubPolicy //One time polices that are cleared after checking, e.g., not user's username
}

// SubPolicy Generic sub policy for one specific role of a password policy
type SubPolicy interface {
	check(s string) error
}

// CasePolicy Minimum number of uppercase and lowercase letters
type CasePolicy struct {
	MinUpper int
	MinLower int
}

func (policy *CasePolicy) check(s string) error {
	numUpper := 0
	numLower := 0
	//Loop over spring counting uppercase and lowercase letters
	for _, character := range s {
		if unicode.IsLetter(character) {
			if unicode.IsUpper(character) {
				numUpper++
			} else {
				numLower++
			}
		}
		//Return once enough letters of each case have been found
		if numLower >= (*policy).MinLower && numUpper >= (*policy).MinUpper {
			return nil
		}
	}
	//Generate error message
	if numLower < (*policy).MinLower && numUpper < (*policy).MinUpper {
		return errors.New("not enough lowercase and uppercase letters")
	} else if numLower < (*policy).MinLower {
		return errors.New("not enough lowercase letters")
	} else {
		return errors.New("not enough uppercase letters")
	}
}

// NumberPolicy Minimum number of numbers
type NumberPolicy struct {
	MinNumbers int
}

func (policy *NumberPolicy) check(s string) error {
	numNumbers := 0
	//Loop over spring counting numbers
	for _, character := range s {
		if unicode.IsNumber(character) {
			numNumbers++
		}
		//Return once enough numbers have been found
		if numNumbers >= (*policy).MinNumbers {
			return nil
		}
	}
	//Generate error message
	return errors.New("not enough numbers")
}

// SpecialPolicy Minimum number of predefined special characters
type SpecialPolicy struct {
	MinSpecial        int
	SpecialCharacters map[rune]bool //The bool does not matter, it is just a cheap way of doing hash-based checking
}

func (policy *SpecialPolicy) check(s string) error {
	numSpecial := 0
	//Loop over spring counting special characters
	for _, character := range s {
		if _, special := (*policy).SpecialCharacters[character]; special {
			numSpecial++
		}
		//Return once enough special characters have been found
		if numSpecial >= (*policy).MinSpecial {
			return nil
		}
	}
	//Generate error message
	return errors.New("not enough special letters")
}

// LengthPolicy Minimum and maximum password length
type LengthPolicy struct {
	MaxLength int //This is not recommended but required by the assignment
	MinLength int
}

func (policy *LengthPolicy) check(s string) error {
	//Check if password is too short
	if len(s) < (*policy).MinLength {
		return errors.New("password is too short")
		//Check if password is too long
	} else if len(s) > (*policy).MaxLength {
		return errors.New("password is too long")
	} else {
		return nil
	}
}

// ProhibitedPasswordsPolicy Predefined prohibited passwords
type ProhibitedPasswordsPolicy struct {
	ProhibitedPasswords map[string]bool //The bool does not matter, it is just a cheap way of doing hash-based checking
}

func (policy *ProhibitedPasswordsPolicy) check(s string) error {
	//Check if the password is prohibited
	if _, prohibited := (*policy).ProhibitedPasswords[s]; prohibited {
		return errors.New("this password is prohibited")
	} else {
		return nil
	}
}

// GetProhibitedPasswords Load prohibited password file into a sub policy
func GetProhibitedPasswords(prohibitedPasswordsFile string) (*ProhibitedPasswordsPolicy, error) {
	prohibitedPolicy := ProhibitedPasswordsPolicy{ProhibitedPasswords: make(map[string]bool)}
	//Open prohibited password file
	file, err := os.Open(prohibitedPasswordsFile)
	if err != nil {
		return nil, err
	}
	//Set file to close after loading is done
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Panic()
		}
	}(file)
	//Load prohibited password from lines in the files
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		prohibitedPolicy.ProhibitedPasswords[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &prohibitedPolicy, nil
}

// ProhibitedRegexesPolicy Predefined prohibited regexes patterns.
// Useful for preventing phone numbers, postal codes, license plates, etc.
type ProhibitedRegexesPolicy struct {
	ProhibitedRegexes []*regexp.Regexp
}

func (policy *ProhibitedRegexesPolicy) check(s string) error {
	for _, regexes := range (*policy).ProhibitedRegexes {
		if regexes.MatchString(s) {
			return errors.New("prohibited pattern use password")
		}
	}
	return nil
}

// GetProhibitedRegexes Load regex password file into a sub policy
func GetProhibitedRegexes(ProhibitedRegexesFile string) (*ProhibitedRegexesPolicy, error) {
	prohibitedRegexesPolicy := ProhibitedRegexesPolicy{[]*regexp.Regexp{}}
	file, err := os.Open(ProhibitedRegexesFile)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Panic()
		}
	}(file)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		compile, err := regexp.Compile(scanner.Text())
		if err != nil {
			return nil, err
		}
		prohibitedRegexesPolicy.ProhibitedRegexes = append(prohibitedRegexesPolicy.ProhibitedRegexes, compile)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &prohibitedRegexesPolicy, nil
}

func runSubPolices(polices *[]SubPolicy, s string) error {
	for _, subPolices := range *polices {
		err := subPolices.check(s)
		if err != nil {
			return err
		}
	}
	return nil
}

// Check All for the sub polices on a string
// This clears the temp polices after check
func (policy *PasswordPolicy) Check(s string) error {
	err := runSubPolices(&(*policy).SubPolices, s)
	if err != nil {
		(*policy).TempPolices = []SubPolicy{}
		return err
	}
	err = runSubPolices(&(*policy).TempPolices, s)
	if err != nil {
		(*policy).TempPolices = []SubPolicy{}
		return err
	}
	(*policy).TempPolices = []SubPolicy{}
	return nil
}
