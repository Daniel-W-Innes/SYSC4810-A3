package strength

import (
	"bufio"
	"errors"
	"log"
	"os"
	"regexp"
	"unicode"
)

type PasswordPolicy struct {
	SubPolices  []SubPolicy
	TempPolices []SubPolicy
}

type SubPolicy interface {
	check(s string) error
}

type CasePolicy struct {
	MinUpper int
	MinLower int
}

func (policy *CasePolicy) check(s string) error {
	numUpper := 0
	numLower := 0
	for _, character := range s {
		if unicode.IsLetter(character) {
			if unicode.IsUpper(character) {
				numUpper++
			} else {
				numLower++
			}
		}
		if numLower >= (*policy).MinLower && numUpper >= (*policy).MinUpper {
			return nil
		}
	}
	if numLower < (*policy).MinLower && numUpper < (*policy).MinUpper {
		return errors.New("not enough lowercase and uppercase letters")
	} else if numLower < (*policy).MinLower {
		return errors.New("not enough lowercase letters")
	} else {
		return errors.New("not enough uppercase letters")
	}
}

type NumberPolicy struct {
	MinNumbers int
}

func (policy *NumberPolicy) check(s string) error {
	numNumbers := 0
	for _, character := range s {
		if unicode.IsNumber(character) {
			numNumbers++
		}
		if numNumbers >= (*policy).MinNumbers {
			return nil
		}
	}
	return errors.New("not enough numbers")
}

type SpecialPolicy struct {
	MinSpecial        int
	SpecialCharacters map[rune]bool
}

func (policy *SpecialPolicy) check(s string) error {
	numSpecial := 0
	for _, character := range s {
		if _, special := (*policy).SpecialCharacters[character]; special {
			numSpecial++
		}
		if numSpecial >= (*policy).MinSpecial {
			return nil
		}
	}
	return errors.New("not enough special letters")
}

type LengthPolicy struct {
	MaxLength int
	MinLength int
}

func (policy *LengthPolicy) check(s string) error {
	if len(s) < (*policy).MinLength {
		return errors.New("password is too short")
	} else if len(s) > (*policy).MaxLength {
		return errors.New("password is too long")
	} else {
		return nil
	}
}

type ProhibitedPasswordsPolicy struct {
	ProhibitedPasswords map[string]bool
}

func (policy *ProhibitedPasswordsPolicy) check(s string) error {
	if _, prohibited := (*policy).ProhibitedPasswords[s]; prohibited {
		return errors.New("this password is prohibited")
	} else {
		return nil
	}
}

func GetProhibitedPasswords(prohibitedPasswordsFile string) (*ProhibitedPasswordsPolicy, error) {
	prohibitedPolicy := ProhibitedPasswordsPolicy{ProhibitedPasswords: make(map[string]bool)}
	file, err := os.Open(prohibitedPasswordsFile)
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
		prohibitedPolicy.ProhibitedPasswords[scanner.Text()] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &prohibitedPolicy, nil
}

type ProhibitedRegexesPolicy struct {
	ProhibitedRegexes []*regexp.Regexp
}

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

func (policy *ProhibitedRegexesPolicy) check(s string) error {
	for _, regexes := range (*policy).ProhibitedRegexes {
		if regexes.MatchString(s) {
			return errors.New("prohibited pattern use password")
		}
	}
	return nil
}
func runSubPolices(polices *[]SubPolicy, s string) error {
	errorsChan := make(chan error)
	for _, subPolices := range *polices {
		go func(subPolices SubPolicy, s string) {
			err := subPolices.check(s)
			if err != nil {
				errorsChan <- err
			}
		}(subPolices, s)
	}
	err := <-errorsChan
	if err != nil {
		return err
	}
	return nil
}

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
