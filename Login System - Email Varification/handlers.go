package main

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	// "github.com/gin-gonic/gin"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var UserId string
var td = make(map[string]string)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// c.HTML(http.StatusOK, "index.html", nil)
	tpl.ExecuteTemplate(w, "index.html", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	_, ok := session.Values["userId"]
	fmt.Println("OK: ", ok)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// c.HTML(http.StatusOK, "home.html", nil)
	td["message"] = "Logged in"
	tpl.ExecuteTemplate(w, "home.html", td)
}

func userInfoGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	asd, ok := session.Values["userId"]
	fmt.Println("OK: ", ok, "userId: ", asd)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// c.HTML(http.StatusOK, "userInfo.html", nil)
	tpl.ExecuteTemplate(w, "profile.html", "User infos")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "login.html", nil)
	case http.MethodPost:
		fmt.Println("Logging in: ")
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hash string
		stmt := "SELECT `UserId`, `PswHash` FROM USERS WHERE `Username`=?"
		row := db.QueryRow(stmt, username)
		err := row.Scan(&UserId, &hash)

		if err != nil {
			fmt.Println("error selecting Hash in DB by Username")
			td["message"] = "check username and password"
			tpl.ExecuteTemplate(w, "login.html", td)
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err == nil {
			session, _ := store.Get(r, "session")
			session.Values["userId"] = UserId
			session.Save(r, w)
			fmt.Println("After login userID: ", UserId)
			td["message"] = "Logged in"
			tpl.ExecuteTemplate(w, "home.html", td)
			return
		} else {
			fmt.Println("Error in CompareHashAndPassword", err)
			td["message"] = "check username and password"
			tpl.ExecuteTemplate(w, "login.html", td)
			return
		}
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tpl.ExecuteTemplate(w, "register.html", nil)
	case http.MethodPost:
		var u User

		u.Username = r.FormValue("username")
		u.Email = r.FormValue("email")
		u.password = r.FormValue("password")

		err := u.ValidateUsername()
		if err != nil {
			tpl.ExecuteTemplate(w, "register.html", err)
			return
		}

		err = u.ValidatePassword()
		if err != nil {
			tpl.ExecuteTemplate(w, "register.html", err)
			return
		}
		var statusCode int
		statusCode, err = u.ValidateEmail()
		if err != nil {
			tpl.ExecuteTemplate(w, "register.html", statusCode)
			return
		}

		exists := u.UsernameExists()
		if exists {
			td["message"] = "Username already taken, please try another"
			tpl.ExecuteTemplate(w, "register.html", td)
			return
		}

		err = u.CreateNewUser()
		if err != nil {
			fmt.Println("create.New err: ", err)
			err = errors.New("there was an issue creating account, please try again")
			tpl.ExecuteTemplate(w, "register.html", err)
			return
		}
		tpl.ExecuteTemplate(w, "register-succ.html", nil)
	}
}

func emailVerHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	var linkVerPass string

	vars := mux.Vars(r)

	u.Username, _ = vars["username"]
	linkVerPass, _ = vars["verPass"]

	err := u.getUserByUsername()
	if err != nil {
		fmt.Println("error selecting verHash in DB by username, err: ", err)
		// c.HTML(http.StatusUnauthorized, "register-succ.html", gin.H{"message": "Please try link in verification email again"})
		td := map[string]string{
			"message": "Please try link in verification email again",
		}
		tpl.ExecuteTemplate(w, "register-succ.html", td)
		return
	}
	td := map[string]string{}
	err = bcrypt.CompareHashAndPassword([]byte(u.verHash), []byte(linkVerPass))
	if err == nil {
		err = u.MakeActive()
		if err != nil {
			// c.HTML(http.StatusBadRequest, "acc-activated.html", gin.H{
			// 	"message": "Please try email confirmation link again",
			// })
			td["message"] = "Please try email confirmation link again"

			tpl.ExecuteTemplate(w, "acc-activated.html", td)
			return
		}
		session, _ := store.Get(r, "session")
		session.Values["userId"] = u.ID
		session.Save(r, w)
		fmt.Println("After register userID: ", u.ID)
		tpl.ExecuteTemplate(w, "acc-activated.html", nil)
		return
	}
	tpl.ExecuteTemplate(w, "register-succ.html", http.StatusUnauthorized)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "userId")
	session.Save(r, w)
	// c.HTML(http.StatusOK, "index.html", nil)
	td["message"] = "Logged out"
	tpl.ExecuteTemplate(w, "index.html", td)
}

func accProfileHandler(w http.ResponseWriter, r *http.Request) {
	var User User
	session, _ := store.Get(r, "session")
	User.ID, _ = session.Values["userId"].(string)
	err := User.SelectById()

	if err != nil {
		fmt.Println(err)
		td["UserMessage"] = "There was an issue displaying profile information"
		tpl.ExecuteTemplate(w, "login.html", td)
		return
	}
	tpl.ExecuteTemplate(w, "profile.html", User)
}

func accProfileEditHandler(w http.ResponseWriter, r *http.Request) {
	var User User
	session, _ := store.Get(r, "session")
	User.ID, _ = session.Values["userId"].(string)

	var td = make(map[string]interface{})
	err := User.SelectById()
	if err != nil {
		td["UserMessage"] = "There was an issue displaying profile information"
		tpl.ExecuteTemplate(w, "login.html", td)
		return
	}
	td["User"] = User
	tpl.ExecuteTemplate(w, "editprofile.html", td)
}

func accEditVerHandler(w http.ResponseWriter, r *http.Request) {
	var td = make(map[string]interface{})
	td["UserMessage"] = "There was an issue editing profile"

	var oldUser User
	var err error
	session, err := store.Get(r, "session")
	if err != nil {
		td["UserMessage"] = "Please login to Edit Profile"
		tpl.ExecuteTemplate(w, "login.html", td)
		return
	}

	oldUser.ID = session.Values["userId"].(string)
	err = oldUser.SelectById()
	if err != nil {
		td["UserMessage"] = "Please login to Edit Profile"
		tpl.ExecuteTemplate(w, "login.html", td)
		return
	}

	var newUser User
	newUser = oldUser
	newUser.Username = r.FormValue("username")
	newUser.Email = r.FormValue("email")
	newUser.password = r.FormValue("password")
	newPassword := r.FormValue("newpassword")
	confirmPassword := r.FormValue("confirmpassword")

	td["User"] = oldUser

	if newUser.Username == oldUser.Username && newUser.Email == oldUser.Email && newPassword == "" {
		td["UserMessage"] = "No changes entered into form"
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}

	err = newUser.verifyPswd()
	if err != nil {
		td["UserMessage"] = err.Error()
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}

	if newPassword != confirmPassword {
		td["UserMessage"] = "New password and confirm password must match"
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}

	err = newUser.ValidateUsername()
	if err != nil {
		td["UserMessage"] = err.Error()
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}

	if newPassword != "" && confirmPassword != "" {
		newUser.password = newPassword
		err = newUser.ValidatePassword()
		if err != nil {
			td["UserMessage"] = err.Error()
			tpl.ExecuteTemplate(w, "editprofile.html", td)
			return
		}
	}
	var userPswByteHash []byte
	userPswByteHash, err = bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		td["UserMessage"] = err.Error()
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}
	newUser.pswHash = string(userPswByteHash)

	_, err = newUser.ValidateEmail()
	if err != nil {
		td["UserMessage"] = err.Error()
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}
	err = newUser.UpdateUser()
	if err != nil {
		td["UserMessage"] = "There was an issue updating User profile, please try again"
		tpl.ExecuteTemplate(w, "editprofile.html", td)
		return
	}

	td["User"] = newUser
	subject := "Profile Updated"
	body := `<h2>Your profile has been updated.</h2>`
	err = oldUser.SendEmail(subject, body)
	if err != nil {
		return
	}
	td["UserMessage"] = errors.New("Your profile has been updated")
	tpl.ExecuteTemplate(w, "editprofile.html", td)
}

func forgotPswHandler(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "forgotpsw.html", nil)
}

func forgotPswValHandler(w http.ResponseWriter, r *http.Request) {

	email := r.FormValue("email")
	fmt.Println("email from forgotPswVal: ", email)

	var td TempData
	td.ErrMessage = "Sorry, there was an issue recovering account, please try again"
	tx, err := db.Begin()
	if err != nil {
		fmt.Println("failed to begin transaction, err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", td.ErrMessage)
		return
	}
	defer tx.Rollback()

	var username string
	row := db.QueryRow("SELECT `Email`, `Username` FROM USERS WHERE `Email`=?", email)
	err = row.Scan(&email, &username)
	if err != nil {
		fmt.Println("email not found in db")
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpswemail.html", td)
		return
	}
	now := time.Now()
	timeout := now.Add(time.Minute * 45)
	rand.Seed(time.Now().UnixNano())

	var alphaNumRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQESTUVWXYZ1234567890")
	emailVerRandRune := make([]rune, 64)

	for i := 0; i < 64; i++ {
		emailVerRandRune[i] = alphaNumRunes[rand.Intn(len(alphaNumRunes)-1)]
	}
	emailVerPassword := string(emailVerRandRune)

	var emailVerPwHash []byte

	emailVerPwHash, err = bcrypt.GenerateFromPassword([]byte(emailVerPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("bcrypt err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", td.ErrMessage)
		return
	}
	var updateEmailVerStmt *sql.Stmt
	updateEmailVerStmt, err = tx.Prepare("UPDATE USER_EMAIL_VER_HASH SET `VerHash`=?, `Timeout`=? WHERE `Email`=?")

	if err != nil {
		fmt.Println("error prepering statement: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", td.ErrMessage)
		return
	}
	defer updateEmailVerStmt.Close()

	emailVerPswHashStr := string(emailVerPwHash)
	var result sql.Result
	result, err = updateEmailVerStmt.Exec(emailVerPswHashStr, timeout, email)

	rowsAff, err := result.RowsAffected()

	if err != nil || rowsAff != 1 {
		fmt.Println("Err at rows aff (line 393): ", err, "rowsAff: ", rowsAff)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an error rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", td.ErrMessage)
		return
	} else {
		fmt.Println("Line 399still good")
	}

	domName := "http://" + MyAddress + ":" + MyPort
	subject := "MyApp Account Recovery"
	body := `<html>
				<h1>Click Link to Verify Email</h1>
				<a href="` + domName + `/forgotpswchange?u=` + username + `&evpw=` + emailVerPassword + `">Change Password</a>
			</html>`

	var User User
	User.Username = username
	User.Email = email
	err = User.SendEmail(subject, body)
	if err != nil {
		fmt.Println("Email send did not word, err: ", err)
		tpl.ExecuteTemplate(w, "forgotpsw.html", err)
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		fmt.Println("there was an error commiting changes, commitErr: ", commitErr)
		tpl.ExecuteTemplate(w, "forgotpsw.html", commitErr)
	}
	tpl.ExecuteTemplate(w, "forgotpswemail.html", nil)
}

func forgotPswEmailVerHandler(w http.ResponseWriter, r *http.Request) {
	var u User

	username := r.FormValue("u")
	emailVerPassword := r.FormValue("evpw")
	userPassword := r.FormValue("password")
	comnfirmPassword := r.FormValue("confirmpassword")

	u.password = userPassword

	fmt.Println("Username: ", username)
	fmt.Println("emailVerPassword: ", emailVerPassword)
	fmt.Println("userPassword: ", userPassword)
	fmt.Println("comnfirmPassword: ", comnfirmPassword)

	var message TempData
	message.ErrMessage = "Sorry, there was an issue recovering account, please try again"
	message.AuthInfo = "?u=" + username + "&evpw" + emailVerPassword

	if userPassword != comnfirmPassword {
		fmt.Println("passwords do not match")
		message.ErrMessage = "passwords must match"
		tpl.ExecuteTemplate(w, "forgotpswchange.html", message.ErrMessage)
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Println("failed to begin tx, err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpswc.html", message.ErrMessage)
		return
	}
	defer tx.Rollback()

	var dbEmailVerHash, timeoutStr string

	row := db.QueryRow("SELECT `VerHash`, `Timeout` FROM USER_EMAIL_VER_HASH WHERE `Username`=?;", username)

	err = row.Scan(&dbEmailVerHash, &timeoutStr)

	fmt.Println("username: ", username)
	fmt.Println("dbEmailVerHash: ", dbEmailVerHash, "timeout: ", timeoutStr)

	if err != nil {
		fmt.Println("VerHash not found in Db:", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", message.ErrMessage)
		return
	}

	// currentTime := time.Now()
	// timeoutTime, _ := time.Parse(time.Now(), timeoutStr)
	// verifyEndTime := currentTime.After(timeoutTime)
	// if verifyEndTime {
	// 	fmt.Println("verifyEndTime: ", verifyEndTime)
	// 	fmt.Println("User: ", username, "did not verify account within 24 hours")
	// 	tpl.ExecuteTemplate(w, "forgotpsw.html", td.ErrMessage)
	// 	if rollbackErr := tx.Rollback(); rollbackErr != nil {
	// 		fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
	// 	}
	// 	return
	// }
	// fmt.Println("dbEmailVerHash: ", dbEmailVerHash)

	err = bcrypt.CompareHashAndPassword([]byte(dbEmailVerHash), []byte(emailVerPassword))
	if err != nil {
		fmt.Println("dbEmailVerHash and hash of emailVerPassword are not the same")
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpsw.html", message.ErrMessage)
		return
	}

	fmt.Println("dbEmailVerHash and hash of EmailVerPassword are the same :)")

	err = u.ValidatePassword()

	if err != nil {
		message.AuthInfo = "?u=" + username + "&evpw" + emailVerPassword
		message.ErrMessage = err.Error()
		tpl.ExecuteTemplate(w, "forgotpswchange.html", message)
		return
	}

	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(userPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("bcrypt err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "register.html", message.ErrMessage)
		return
	}

	stmt := "UPDATE USERS SET `PswHash`=? WHERE `Username`=?"
	updateHashStmt, err := tx.Prepare(stmt)
	if err != nil {
		fmt.Println("error preparing updateHashStmt err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "forgotpswchange", message.ErrMessage)
		return
	}
	defer updateHashStmt.Close()

	var result sql.Result
	result, err = updateHashStmt.Exec(hash, username)
	rowsAff, _ := result.RowsAffected()
	fmt.Println("rowsAff: ", rowsAff)
	if err != nil || rowsAff != 1 {
		fmt.Println("error inserting new user, err: ", err)
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			fmt.Println("there was an issue rolling back changes, rollbackErr: ", rollbackErr)
		}
		tpl.ExecuteTemplate(w, "verifyemail.html", message.ErrMessage)
		return
	}

	if commitErr := tx.Commit(); commitErr != nil {
		fmt.Println("there was an error commiting changes, commitErr: ", commitErr)
		tpl.ExecuteTemplate(w, "forgotpsw.html", message.ErrMessage)
		return
	}

	fmt.Println("forgottten password has been reset")
	td["message"] = "Password Successfully Updated"
	tpl.ExecuteTemplate(w, "login.html", td)
}

func forgotPswChangeHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("u")
	emailVerPassword := r.FormValue("evpw")
	fmt.Println("username in ChangeHandler: ", username, "and the emailVerPass: ", emailVerPassword)
	var td TempData
	td.AuthInfo = "?u=" + username + "&evpw=" + emailVerPassword
	tpl.ExecuteTemplate(w, "forgotpswchange.html", td)
}

/*func emailverGetHandler(c *gin.Context) {

	var u User
	u.Username = c.Param("username")
	linkVerPass := c.Param("verPass")

	err := u.getUserByUsername()
	if err != nil {
		fmt.Println("error selecting verHash in DB by username, err: ", err)
		c.HTML(http.StatusUnauthorized, "register-succ.html", gin.H{"message": "Please try link in verification email again"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(u.verHash), []byte(linkVerPass))
	if err == nil {
		err = u.MakeActive()
		if err != nil {
			c.HTML(http.StatusBadRequest, "acc-activated.html", gin.H{
				"message": "Please try email confirmation link again",
			})
			return
		}
		c.HTML(http.StatusOK, "acc-activated.html", nil)
		return
	}
	c.HTML(http.StatusUnauthorized, "register-succ.html", gin.H{"message": "Please try link in verification email again"})
}*/

// func registerGetHandler(c *gin.Context) {
// 	c.HTML(http.StatusOK, "register.html", nil)
// }

/*func registerPostHandler(c *gin.Context) {

	var u User

	u.Username = c.PostForm("username")
	u.Email = c.PostForm("email")
	u.password = c.PostForm("password")

	err := u.ValidateUsername()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"massage": err,
			"user":    u,
		})
		return
	}
	err = u.ValidatePassword()
	if err != nil {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"massage": err,
			"user":    u,
		})
		return
	}
	var statusCode int
	statusCode, err = u.ValidateEmail()
	if err != nil {
		c.HTML(statusCode, "register.html", gin.H{
			"massage": err,
			"user":    nil,
		})
		return
	}
	exists := u.UsernameExists()
	if exists {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"massage": "Username already taken, please try another",
			"user":    u,
		})
		return
	}
	err = u.CreateNewUser()
	if err != nil {
		fmt.Println("create.New err: ", err)
		err = errors.New("there was an issue creating account, please try again")
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"massage": err,
			"user":    u,
		})
		return
	}
	session, _ := store.Get(c.Request, "session")
	session.Values["userId"] = UserId
	session.Save(c.Request, c.Writer)
	c.HTML(http.StatusOK, "register-succ.html", gin.H{})
}*/

// func loginGetHandler(c *gin.Context) {
// 	c.HTML(http.StatusOK, "login.html", nil)
// }

/*func loginPostHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	var hash string
	stmt := "SELECT `UserId`, `PswHash` FROM USERS WHERE `Username`=?"
	row := db.QueryRow(stmt, username)
	err := row.Scan(&UserId, &hash)
	if err != nil {
		fmt.Println("error selecting Hash in DB by Username")
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"message": "check username and password",
		})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil {
		session, _ := store.Get(c.Request, "session")
		session.Values["userId"] = UserId
		session.Save(c.Request, c.Writer)

		http.Redirect(c.Writer, c.Request, "/home", http.StatusOK)
		return
	}
	fmt.Println("incorrect password")
	c.HTML(http.StatusBadRequest, "login.html", gin.H{
		"message": "check username and password",
	})
}*/
