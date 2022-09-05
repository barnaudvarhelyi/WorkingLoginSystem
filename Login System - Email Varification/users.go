package main

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"
	"unicode"

	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

func (u *User) getUserByUsername() error {
	stmt := "SELECT * FROM USERS WHERE `Username`=?"
	fmt.Println(u.Username)
	row := db.QueryRow(stmt, u.Username)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.pswHash, &u.CreatedAt, &u.Active, &u.verHash, &u.timeout)
	if err != nil {
		fmt.Println("getUser() error selecting User, err: ", err)
		return err
	}
	return nil
}

func (u *User) ValidateUsername() error {
	for _, char := range u.Username {
		if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
			return errors.New("Only alphanumeric characters allowed for username")
		}
	}
	if 5 <= len(u.Username) && len(u.Username) <= 50 {
		return nil
	}
	return errors.New("username lenght must be greater than 4 and less than 51 characters")
}

func (u *User) ValidatePassword() error {
	err := passwordvalidator.Validate(u.password, minEntropyBits)
	return err
}

func (u *User) ValidateEmail() (statusCode int, err error) {

	res, err := verifier.Verify(u.Email)
	if err != nil {
		fmt.Println("verify email address failed, error: ", err)
		return http.StatusInternalServerError, err
	}
	if !res.Syntax.Valid {
		err = errors.New("email address syntax is invalid")
		fmt.Println(err)
		return http.StatusBadRequest, err
	}
	if res.Disposable {
		err = errors.New("sorry, we do not accept disposable email address")
		return http.StatusBadRequest, err
	}
	if res.Suggestion != "" {
		err = errors.New("email address is not reachtable, looking for " + res.Suggestion + " instead?")
		return http.StatusBadRequest, err
	}
	if res.Reachable == "no" {
		err = errors.New("email address is not reachable")
		return http.StatusBadRequest, err
	}
	if !res.HasMxRecords {
		err = errors.New("domain entered not properly setup to recieve emails, MX record not found")
		return http.StatusBadRequest, err
	}
	return http.StatusOK, nil
}

func (u *User) UsernameExists() (exists bool) {
	exists = true
	stmt := "SELECT `UserId` FROM USERS WHERE `Username` = ?"
	row := db.QueryRow(stmt, u.Username)
	var uID string
	err := row.Scan(&uID)
	if err == sql.ErrNoRows {
		return false
	}
	return exists
}

func (u *User) CreateNewUser() error {
	var hash []byte
	hash, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("bcrypt err", err)
		return err
	}

	CreatedAt := time.Now().Local()

	rand.Seed(time.Now().UnixNano())

	var alphaNumRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQESTUVWXYZ1234567890")
	emailVerRandRune := make([]rune, 64)

	for i := 0; i < 64; i++ {
		emailVerRandRune[i] = alphaNumRunes[rand.Intn(len(alphaNumRunes)-1)]
	}
	fmt.Println("emailVerRandRune: ", emailVerRandRune)
	emailVerPassword := string(emailVerRandRune)
	fmt.Println("emailVerPassword: ", emailVerPassword)

	var emailVerPWhash []byte

	emailVerPWhash, err = bcrypt.GenerateFromPassword([]byte(emailVerPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("bcrypt err: ", err)
		return err
	}
	fmt.Println("emailVerPWhash: ", emailVerPWhash)
	u.verHash = string(emailVerPWhash)

	timeout := time.Now().Local().AddDate(0, 0, 2)
	fmt.Println("u.timeout: ", timeout)

	var tx *sql.Tx
	tx, err = db.Begin()
	if err != nil {
		fmt.Println("failed to begin transaction, err", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		return err
	}
	defer tx.Rollback()

	var insertStmt *sql.Stmt
	insertStmt, err = tx.Prepare("INSERT INTO USERS (`Username`, `Email`, `PswHash`,`CreatedAt`, `Active`, `VerHash`, `Timeout`) VALUES (?, ?, ?, ?, ?, ?, ?)")

	if err != nil {
		fmt.Println("error preparing statement: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
	}
	defer insertStmt.Close()

	var result sql.Result

	result, err = insertStmt.Exec(u.Username, u.Email, hash, CreatedAt, 0, u.verHash, timeout)

	aff, err := result.RowsAffected()

	if aff == 0 {
		fmt.Println("error at inserting: ", err)
		return err
	}

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
		return err
	}

	var tx2 *sql.Tx
	tx2, err = db.Begin()
	if err != nil {
		fmt.Println("failed to begin transaction, err", err)
		if rollbackErr := tx2.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		return err
	}
	defer tx2.Rollback()

	var insertStmt2 *sql.Stmt
	insertStmt2, err = tx.Prepare("INSERT INTO USER_EMAIL_VER_HASH (`Username`, `Email`, `VerHash`, `Timeout`) VALUES (?, ?, ?, ?)")

	if err != nil {
		fmt.Println("error preparing statement: ", err)
		if rollbackErr := tx2.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
	}
	defer insertStmt2.Close()

	var result2 sql.Result
	result2, err = insertStmt2.Exec(u.Username, u.Email, u.verHash, timeout)

	aff, err = result2.RowsAffected()
	if aff == 0 {
		fmt.Println("Error at inserting: ", err)
		return err
	}

	if err != nil {
		if rollbackErr := tx2.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
		return err
	}

	var domName string
	// if servLog == "local" {
	// 	domName = "http://localhost:8080"
	// } else {
	// 	if useHTTPS == "true" {
	// 		domName = "https://" + domainName
	// 	} else {
	// 		domName = "http://" + domainName
	// 	}
	// }
	// fmt.Println("domName: ", domName)
	domName = "http://localhost:8080"
	subject := "Email Verification"
	HTMLbody :=
		`<html>
			<h1>Click Link to Verify Email</h1>
			<a href="` + domName + `/emailver/` + u.Username + `/` + emailVerPassword + `">Click to verify email</a>
		</html>`

	err = u.SendEmail(subject, HTMLbody)

	if err != nil {
		fmt.Println("issue sending verification email")
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
	}
	if commitErr := tx.Commit(); commitErr != nil {
		fmt.Println("error commiting changes, err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
			return err
		}
	}
	return nil
}

func (u *User) MakeActive() error {
	stmt, err := db.Prepare("UPDATE USERS SET `Active`=TRUE WHERE `UserId`=?")
	if err != nil {
		fmt.Println("error preparing statement to update Active")
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(u.ID)
	if err != nil {
		fmt.Println("error executing statemnt to update Active")
		return err
	}
	return nil
}

func (u *User) SelectById() error {
	stmt := "SELECT `UserId`, `Username`, `Email`, `PswHash`, `CreatedAt`, `Active`, `VerHash`, `Timeout` FROM USERS WHERE `UserId`=?"
	row := db.QueryRow(stmt, &u.ID)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.pswHash, &u.CreatedAt, &u.Active, &u.verHash, &u.timeout)
	if err != nil {
		return err
	}
	return err
}

func (u *User) verifyPswd() error {
	err := bcrypt.CompareHashAndPassword([]byte(u.pswHash), []byte(u.password))
	if err != nil {
		err = errors.New("Username and password do not match!")
		return err
	}

	if u.Active == 0 {
		err = errors.New("User email not verified yet!")
		return err
	}
	return nil
}

func (u *User) UpdateUser() error {
	var updateUserStmt *sql.Stmt
	updateUserStmt, err := db.Prepare("UPDATE USERS SET `Username`=?, `Email`=?, `PswHash`=?, `Active`=?, `VerHash`=?, `Timeout`=? WHERE `UserId`=?;")
	if err != nil {
		fmt.Println("error preparring statement to update user in Db with Update, err:", err)
		return err
	}
	defer updateUserStmt.Close()
	var result sql.Result

	result, err = updateUserStmt.Exec(u.Username, u.Email, u.pswHash, u.Active, u.verHash, u.timeout, u.ID)

	rowsAff, _ := result.RowsAffected()

	if err != nil {
		fmt.Println("there was an erorr updating user in Update() err:", err)
		return errors.New("number of rows affected not equal to one")
	}
	if rowsAff != 1 {
		fmt.Println("rows affected not equal to one:", err)
		return errors.New("number of rows affected not equal to one")
	}
	return err
}
