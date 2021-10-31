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
	"strings"
)

const bcryptCost = 15
const bassPath = "/sensitive_files"

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

//arrayToUsers Create a user structs mapped by username from the nested arrays extracted from the passwd file.
func arrayToUsers(records [][]string) map[string]UserRecord {
	output := make(map[string]UserRecord)
	var user UserRecord
	for _, record := range records {
		//This could be made more complicated by parsing headers, but it's not necessary for this assignment.
		user = UserRecord{record[0], record[1], record[2], record[3]}
		output[user.username] = user
	}
	return output
}

//readCSV Open a CSV file, read its contents to nested arrays, then close it.
func readCSV(fileName string) ([][]string, error) {
	//Open the csv file
	file, err := os.Open(fileName)
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
	//Read and decode the csv in to nested arrays
	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	return records, nil
}

//getUsers Get system users
func getUsers(passwordFile string) (map[string]UserRecord, error) {
	//Get CSV file contents
	records, err := readCSV(passwordFile)
	if err != nil {
		return nil, err
	}
	//Convert nested arrays to users
	return arrayToUsers(records), nil
}

//getPatients Get relationships between patients and doctors.
//Formatted with the doctor userId as the key and an array of patient userIds as the value.
func getPatients(patientsFile string) (map[string][]string, error) {
	output := make(map[string][]string)
	//Get CSV file contents
	records, err := readCSV(patientsFile)
	if err != nil {
		return nil, err
	}
	//Convert nested arrays to map of arrays
	//e.g. [[1,2],[1,4],[2,5]] -> {1:[2,4],2:[5]}
	for _, record := range records {
		if user, ok := output[record[0]]; ok {
			output[record[0]] = append(user, record[1])
		} else {
			output[record[0]] = []string{record[1]}
		}
	}
	return output, nil
}

//getCredentials Get login credentials from user input
func getCredentials(hidePassword bool) (User, error) {
	var username string
	var password []byte
	//Get username from user
	fmt.Print("Enter username: ")
	_, err := fmt.Scanln(&username)
	if err != nil {
		return User{}, err
	}
	//Get password from user
	fmt.Print("Enter password: ")
	if hidePassword {
		//If enabled hide the password as the user is typing it. this is not operating system independent.
		password, err = term.ReadPassword(int(os.Stdin.Fd()))
	} else {
		_, err = fmt.Scanln(&password)
	}
	if err != nil {
		return User{}, err
	}
	fmt.Println()
	//Renew return username and password as user struct
	return User{username: username, password: password}, nil
}

//generatePasswd Generate passwd file formatted as a CSV from user input.
func generatePasswd(passwordFile string, policy *strength.PasswordPolicy, hidePassword bool) error {
	//Create empty password file
	file, err := os.Create(passwordFile)
	if err != nil {
		return err
	}
	//Setup writer to write users into password file
	writer := csv.NewWriter(file)
	defer writer.Flush()
	var role string
	var userInput string
	c := true
	userID := 0
	for c {
		//Get credentials for a new user
		user, err := getCredentials(hidePassword)
		if err != nil {
			return err
		}
		if strings.ContainsRune(user.username, ',') {
			fmt.Println("Username cannot contain ','")
			continue
		}
		passwordKeyChan := make(chan []byte)
		errorChan := make(chan error)
		//Start hashing password concurrently, to main process
		go func(user User) {
			passwordKey, err := bcrypt.GenerateFromPassword(preHash(user.password), bcryptCost)
			passwordKeyChan <- passwordKey
			errorChan <- err
		}(user)
		//Add a new password policy to ensure that the user cannot have a password of his own username
		(*policy).TempPolices = append((*policy).TempPolices, &strength.ProhibitedPasswordsPolicy{ProhibitedPasswords: map[string]bool{user.username: true}})
		err = (*policy).Check(string(user.password))
		if err != nil {
			fmt.Println(err)
			continue
		}
		//Get the new users role
		fmt.Print("Enter role: ")
		_, err = fmt.Scanln(&role)
		if err != nil {
			return err
		}
		if strings.ContainsRune(role, ',') {
			fmt.Println("Role cannot contain ','")
			continue
		}
		//Get password hash from concurrent thread
		passwordKey := <-passwordKeyChan
		err = <-errorChan
		close(passwordKeyChan)
		close(errorChan)
		if err != nil {
			return err
		}
		//Write user into file.
		//Itoa converts integers to strings
		err = writer.Write([]string{user.username, string(passwordKey), strconv.Itoa(userID), role})
		if err != nil {
			return err
		}
		//Check if the user wants to input more users
		fmt.Print("Do you want to continue (y/n)? ")
		_, err = fmt.Scanln(&userInput)
		if err != nil {
			return err
		}
		c = userInput == "y"
		userID++
	}
	return nil
}

//preHash and encode the user inputted password
func preHash(password []byte) []byte {
	//Setup to hash the password with the pepper key as the secret
	hashedPassword := hmac.New(sha256.New, []byte(os.Getenv("PEPPER_KEY")))
	hashedPassword.Write(password)
	//Encode the resulting hash as Base64
	return []byte(base64.StdEncoding.EncodeToString(hashedPassword.Sum(nil)))
}

//checkPassword Check the user inputted password against the password key.
//Return the user's record and true if the user successfully logged-in.
func checkPassword(user User, users map[string]UserRecord) (UserRecord, bool) {
	if record, ok := users[user.username]; ok {
		//Prehash the password and then check it against the password key
		if bcrypt.CompareHashAndPassword([]byte(record.passwordKey), preHash(user.password)) == nil {
			return record, true
		}
	}
	return UserRecord{}, false
}

//getPasswordPolicy Generate password policy from information provided in assignment.
//This uses the strength module defined in the same repo.
func getPasswordPolicy() *strength.PasswordPolicy {
	//Load prohibited passwords from prohibitive password file
	prohibitedPasswords, err := strength.GetProhibitedPasswords(bassPath + "/prohibited_passwords")
	if err != nil {
		return nil
	}
	//Load prohibited regex from prohibited regex file
	prohibitedRegexes, err := strength.GetProhibitedRegexes(bassPath + "/prohibited_regexes")
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
	//check environment variable to see if a password file should be generated
	if os.Getenv("GENERATE_PASSWD") == "y" {
		err := generatePasswd(bassPath+"/passwd", passwordPolicy, hidePassword)
		if err != nil {
			log.Panic(fmt.Errorf("failed to create passwd: %w", err))
		}
	}

	usersChan := make(chan map[string]UserRecord)
	patientsMapChan := make(chan map[string][]string)
	//Load password file and patient's file Concurrently, to main process
	go func() {
		users, err := getUsers(bassPath + "/passwd")
		if err != nil {
			log.Panic("failed to open passwd: " + err.Error())
		}
		usersChan <- users
		patientsMap, err := getPatients(bassPath + "/patients")
		if err != nil {
			log.Panic("failed to open patients: " + err.Error())
		}
		patientsMapChan <- patientsMap
	}()

	fmt.Print("\n\nMedView Imaging\n" +
		"Medical Information Management System\n" +
		"-----------------------------------------------------\n")
	//Get login info from the user
	user, err := getCredentials(hidePassword)
	if err != nil {
		log.Panic("failed get credentials")
	}
	//Check user login info
	record, ok := checkPassword(user, <-usersChan)
	if ok {
		fmt.Println("ACCESS GRANTED")
	} else {
		fmt.Println("Bad username or password")
		return
	}
	//Print out user's permissions
	if patients, ok := (<-patientsMapChan)[record.userId]; ok {
		fmt.Printf("User permissions:\n role: %s\n patient IDs: %s\n", record.role, patients)
	} else {
		fmt.Printf("User permissions:\n role: %s\n", record.role)
	}
}
