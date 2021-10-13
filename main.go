package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"github.com/Daniel-W-Innes/SYSC4810-A3/strength"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"log"
	"os"
	"strconv"
)

const bcryptCost = 15

type UserRecord struct {
	username    string
	passwordKey string
	userId      string
	role        string
}

type User struct {
	username string
	password []byte
}

func arrayToUsers(records [][]string) map[string]UserRecord {
	output := make(map[string]UserRecord)
	var user UserRecord
	for _, record := range records {
		user = UserRecord{record[0], record[1], record[2], record[3]}
		output[user.username] = user
	}
	return output
}

func getUsers(passwordFile string) (map[string]UserRecord, error) {
	file, err := os.Open(passwordFile)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Panic()
		}
	}(file)
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	return arrayToUsers(records), nil
}

func getPatients(patientsFile string) (map[string][]string, error) {
	output := make(map[string][]string)
	file, err := os.Open(patientsFile)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Panic()
		}
	}(file)
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if user, ok := output[record[0]]; ok {
			output[record[0]] = append(user, record[1])
		} else {
			output[record[0]] = []string{record[1]}
		}
	}
	return output, nil
}

func getCredentials(hidePassword bool) (User, error) {
	var username string
	var password []byte
	fmt.Print("Enter username: ")
	_, err := fmt.Scanln(&username)
	if err != nil {
		return User{}, err
	}
	fmt.Print("Enter password: ")
	if hidePassword {
		password, err = term.ReadPassword(int(os.Stdin.Fd()))
	} else {
		_, err = fmt.Scanln(&password)
	}
	if err != nil {
		return User{}, err
	}
	fmt.Println()
	return User{username: username, password: password}, nil
}

func generatePasswd(passwordFile string, policy *strength.PasswordPolicy, hidePassword bool) error {
	file, err := os.Create(passwordFile)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	defer writer.Flush()
	var role string
	var userInput string
	c := true
	i := 0
	for c {
		user, err := getCredentials(hidePassword)
		if err != nil {
			return err
		}
		passwordKeyChan := make(chan []byte)
		errorChan := make(chan error)
		go func(user User) {
			passwordKey, err := bcrypt.GenerateFromPassword(preHash(user.password), bcryptCost)
			passwordKeyChan <- passwordKey
			errorChan <- err
		}(user)
		(*policy).TempPolices = append((*policy).TempPolices, &strength.ProhibitedPasswordsPolicy{ProhibitedPasswords: map[string]bool{user.username: true}})
		err = (*policy).Check(string(user.password))
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Print("Enter role: ")
		_, err = fmt.Scanln(&role)
		if err != nil {
			return err
		}
		passwordKey := <-passwordKeyChan
		err = <-errorChan
		close(passwordKeyChan)
		close(errorChan)
		if err != nil {
			return err
		}
		err = writer.Write([]string{user.username, string(passwordKey), strconv.Itoa(i), role})
		if err != nil {
			return err
		}
		fmt.Print("Do you want to continue (y/n)? ")
		_, err = fmt.Scanln(&userInput)
		if err != nil {
			return err
		}
		c = userInput == "y"
		i++
	}
	return nil
}

func preHash(password []byte) []byte {
	hashedPassword := hmac.New(sha256.New, []byte(os.Getenv("PEPPER_KEY")))
	hashedPassword.Write(password)
	return []byte(base64.StdEncoding.EncodeToString(hashedPassword.Sum(nil)))
}

func checkPassword(user User, users map[string]UserRecord) (UserRecord, bool) {
	if record, ok := users[user.username]; ok {
		if bcrypt.CompareHashAndPassword([]byte(record.passwordKey), preHash(user.password)) == nil {
			return record, true
		}
	}
	return UserRecord{}, false
}

func getPasswordPolicy() *strength.PasswordPolicy {
	prohibitedPasswords, err := strength.GetProhibitedPasswords("sensitive_files/prohibited_passwords")
	if err != nil {
		return nil
	}
	prohibitedRegexes, err := strength.GetProhibitedRegexes("sensitive_files/prohibited_regexes")
	if err != nil {
		return nil
	}
	return &strength.PasswordPolicy{SubPolices: []strength.SubPolicy{
		&strength.LengthPolicy{MinLength: 8, MaxLength: 12},
		&strength.CasePolicy{MinLower: 1, MinUpper: 1},
		&strength.NumberPolicy{MinNumbers: 1},
		&strength.SpecialPolicy{MinSpecial: 1, SpecialCharacters: map[rune]bool{'!': true, '@': true, '#': true, '$': true, '%': true, '?': true, '∗': true}},
		prohibitedPasswords,
		prohibitedRegexes,
	}}
}

func main() {
	hidePassword := os.Getenv("HIDE_PASSWORD") != "n"
	passwordPolicy := getPasswordPolicy()
	if os.Getenv("GENERATE_PASSWD") == "y" {
		err := generatePasswd("sensitive_files/passwd", passwordPolicy, hidePassword)
		if err != nil {
			return
		}
	}
	users, err := getUsers("sensitive_files/passwd")
	if err != nil {
		return
	}
	patientsMap, err := getPatients("sensitive_files/patients")
	if err != nil {
		return
	}

	fmt.Print("\n\nMedView Imaging\n" +
		"Medical Information Management System\n" +
		"-----------------------------------------------------\n")
	user, err := getCredentials(hidePassword)
	if err != nil {
		return
	}
	record, ok := checkPassword(user, users)
	if ok {
		fmt.Println("ACCESS GRANTED")
	} else {
		fmt.Println("Bad username or password")
		return
	}
	if patients, ok := patientsMap[record.userId]; ok {
		fmt.Printf("User permissions:\n role: %s\n patient IDs: %s\n", record.role, patients)
	} else {
		fmt.Printf("User permissions:\n role: %s\n", record.role)
	}
}
