package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/amankhys/login-page-go/crypt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// setting global variables to be used
var (
	SessionIDLength = 56

	ErrValueTooLong        = errors.New("cookie value too long")
	ErrInvalidValue        = errors.New("cookie value is invalid")
	ErrCookieAlreadyExists = errors.New("cookie already exists.")

	db *sql.DB
)

type BoolInt int

func printBool(b *BoolInt) {
	fmt.Println(b)
}

const False BoolInt = 0
const True BoolInt = 1

// user modal to take and send data to users table
type User struct {
	ID        int
	Username  string
	Email     string
	Password  string
	SessionID string
	IsAdmin   BoolInt
}

// init function to establish db connection
func init() {
	var err error
	log.Println("entering init()")
	db, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection successfully initialized")
}

func main() {
	// db logic
	defer db.Close()

	// backend logic
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/signup-page", signupPageHandler)
	mux.HandleFunc("/signup", signupHandler)
	mux.HandleFunc("/addUser", addUserHandler)
	mux.HandleFunc("/updateUser", updateUserHandler)
	mux.HandleFunc("/deleteUser", deleteUserHandler)

	log.Print("Listenting on: 4444...")
	err := http.ListenAndServe(":4444", mux)
	if err != nil {
		log.Fatal(err)
	}
}

// ////////////////////
// Handler functions
// ////////////////////

func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore favicon requests
	if r.URL.Path == "/favicon.ico" {
		return
	}

	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "-1")

	cookie, err := readCookie(r, "SessionID")
	if cookie == nil {
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if err != nil {
		log.Println("error while reading cookie: ", err)
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	value, err := crypt.Decrypt(cookie.Value)
	fmt.Printf("cookie sessionID: %s \n", value)
	if err != nil {
		log.Printf("%v", fmt.Errorf("error while decrypting value from cookie.Value: %w", err))
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	user := getUserBySessionID(value)
	if checkSession(value) && user.IsAdmin == False {
		homePageServer(w, cookie)
		return
	} else if checkSession(value) && user.IsAdmin == True {
		adminPageServer(w)
		return
	} else {
		fmt.Println("sessionid is not in  db.")
		http.ServeFile(w, r, "./static/index.html")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	//login handler logic
	var users = getUsers(db)
	var SessionID string
	var rUser User
	rUser.Username, rUser.Password = r.FormValue("username"), r.FormValue("password")
	rUser.Username = strings.ToLower(rUser.Username)
	var flag bool
	for _, user := range users {
		if rUser.Username == user.Username && rUser.Password == user.Password {
			flag = true
			SessionID = getCustomID()
			saveSessionID(user, SessionID)
		} else if rUser.Username == user.Username && rUser.Password != user.Password {
			http.Error(w, "entered incorrect password", http.StatusBadRequest)
		}
	}

	if flag {
		encryptedID, err := crypt.Encrypt(SessionID)
		if err != nil {
			fmt.Println("error while encrypting SessionID to send as cookie.Value:", err)
		}
		writeCookie(w, encryptedID)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore favicon requests
	if r.URL.Path == "/favicon.ico" {
		return
	}

	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "-1")

	cookie, err := readCookie(r, "SessionID")
	if err == ErrInvalidValue {
		http.Error(w, "cookie has been alterned/changed without permission.", http.StatusBadRequest)
	}
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	// clear the session ID from database
	if oldCookie, err := r.Cookie("SessionID"); err == nil {
		value, _ := crypt.Decrypt(oldCookie.Value)
		if user := getUserBySessionID(value); user.Username != "" {
			saveSessionID(user, "-1")
		}
	}
	log.Println("deleted cookie:", cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	var err error
	var users []User
	user.Username, user.Email, user.Password = r.FormValue("username"), r.FormValue("email"), r.FormValue("password")
	//  make the entered Username as case-insensitive
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	user.Password, err = crypt.Encrypt(user.Password)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	users = getUsers(db)
	for _, v := range users {
		if v.Username == user.Username {
			str := fmt.Sprintf("User already exists. You can't Sign up as the user: %v\n", user.Username)
			http.Error(w, str, http.StatusBadRequest)
		}
	}
	query := "insert into users (username,email, password) values (?,?, ?);"
	_, err = db.Exec(query, user.Username, user.Email, user.Password)
	if err != nil {
		log.Println("error while inserting values: ", err)
	}

	SessionID := getCustomID()
	user = getUser(user.Username)
	saveSessionID(user, SessionID)
	cryptedID, err := crypt.Encrypt(SessionID)
	if err != nil {
		log.Println("error while converting SessionID to encryptedID to write on cookie in sign-up.", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	writeCookie(w, cryptedID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func signupPageHandler(w http.ResponseWriter, r *http.Request) {
	// Disable caching for dynamic content
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "-1")
	cookie, err := readCookie(r, "SessionID")
	if err != nil {
		log.Println(err)
	}
	if cookie != nil {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	http.ServeFile(w, r, "./static/signup.html")
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	var err error
	user.Username = r.FormValue("username")
	user.Email = r.FormValue("email")
	user.Password = r.FormValue("password")
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	user.Password, err = crypt.Encrypt(user.Password)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	flag := checkIfUserExists(user.Username)
	if flag {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	query := "insert into users (username, email, password) values (?,?,?);"
	_, err = db.Exec(query, user.Username, user.Email, user.Password)
	if err != nil {
		log.Println(err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "SessionID")
	if cookie == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	value, err := crypt.Decrypt(cookie.Value)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	isAdmin := checkIfUserIsAdminFromSessionID(value)
	// return if the user trying to update is not admin
	if !isAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var user User
	user.Username = r.FormValue("username")
	user.Email = r.FormValue("email")
	user.ID, err = strconv.Atoi(r.FormValue("id"))
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	user.Username = strings.ToLower(user.Username)
	user.Email = strings.ToLower(user.Email)
	flag := checkIfUserExistsWithID(user.ID)
	if !flag {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	fmt.Printf("updating username: %s \n", user.Username)
	query := "update users set username = ?, email = ? where id= ?;"
	result, err := db.Exec(query, user.Username, user.Email, user.ID)
	if err != nil {
		log.Println(err)
	}
	k, err := result.RowsAffected()
	if err != nil {
		log.Println(err)
	}
	if k > 1 {
		log.Println("more than 1 number of rows are affected.")
	} else if k == 0 {
		log.Println("update user did not happen.")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	user.Username = r.FormValue("username")
	user.Username = strings.ToLower(user.Username)
	var is_admin = r.FormValue("is_admin")
	user.IsAdmin = stringToBoolInt(is_admin)
	if user.IsAdmin == True {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	flag := checkIfUserExists(user.Username)
	if !flag {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	query := "delete from users where username = ?;"
	result, err := db.Exec(query, user.Username)
	if err != nil {
		log.Println(err)
	}
	k, err := result.RowsAffected()
	if k > 1 {
		log.Println("more than 1 number of rows are affected.")
	} else if k == 0 {
		log.Println("delete user did not happen.")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// //////////////
// db functions
// //////////////

func getUsers(db *sql.DB) []User {
	var users []User
	rows, err := db.Query("select * from users;")
	if err != nil {
		log.Println("cannot take row from db users", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.SessionID, &user.IsAdmin)
		if err != nil {
			log.Println(err)
			break
		}
		users = append(users, user)
	}
	return users
}

// func(username string) get User from db table users;
func getUser(username string) User {
	var user User
	query := "select * from users where username = ?;"
	row := db.QueryRow(query, username)
	row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.SessionID, &user.IsAdmin)
	return user
}

// func(sessionID string) gives back populated User if sessionID exists
func getUserBySessionID(SessionID string) User {
	var user User
	query := "select * from users where session_id = ?;"
	row := db.QueryRow(query, SessionID)
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.SessionID, &user.IsAdmin)
	if err == sql.ErrNoRows {
		return User{}
	}
	return user
}

func checkIfUserExists(username string) bool {
	var users []User
	users = getUsers(db)
	for _, user := range users {
		if username == user.Username {
			return true
		}
	}
	return false
}

func checkIfUserExistsWithID(id int) bool {
	var users []User
	users = getUsers(db)
	for _, user := range users {
		if id == user.ID {
			return true
		}
	}
	return false
}

// save SessionID to database after being created on login/signup using username
func saveSessionID(user User, SessionID string) {
	query := "update users set session_id = ? where username = ?;"
	result, err := db.Exec(query, SessionID, user.Username)
	k, errRows := result.RowsAffected()
	if errRows != nil {
		log.Printf("error while taking number of rows affected: %v\n", err)
		return
	}
	if err != nil {
		log.Printf("unable to update SessionID: %s for id: %d\n%v\n", SessionID, user.ID, err)
	}
	if k != 1 {
		log.Println("db error: more than 1 rows affected while updating session_id;")
	}
}

func checkIfUserIsAdminFromSessionID(sessionid string) bool {
	var user User = getUserBySessionID(sessionid)
	if user.IsAdmin == True {
		return true
	}
	return false
}

// //////////////////
// Session functions
// //////////////////

// SessionID authenticating function(takes in sessionID string)
func checkSession(SessionID string) bool {
	var users []User
	var ids []string
	var check bool
	users = getUsers(db)

	for _, user := range users {
		ids = append(ids, user.SessionID)
	}
	for i := 0; i < len(ids); i++ {
		if SessionID == ids[i] {
			check = true
		}
	}
	return check
}

// Write SessionID cookie function
func writeCookie(w http.ResponseWriter, SessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "SessionID",
		Value:    SessionID,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Reead SessionID cookie function
func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookie, err := r.Cookie(name)

	if cookie == nil {
		log.Println("cookie does not exist.")
		return nil, http.ErrNoCookie
	}

	// SessionID length is checked for 2 times it since it has been decoded to hex format before sending
	if len(cookie.Value) != SessionIDLength*2 {
		log.Printf("invalid cookie value.\n")
		return nil, ErrInvalidValue
	}
	if err != nil {
		log.Println("unable to read the cookie.")
		return nil, err
	}
	return cookie, nil
}

/////////////////////////////
// Handler helper functions
/////////////////////////////

func adminPageServer(w http.ResponseWriter) {
	users := getUsers(db)
	data := struct {
		Users []User
	}{
		Users: users,
	}

	tmpl := template.Must(template.ParseFiles("./static/admin.html"))
	tmpl.Execute(w, data)
	return
}

func homePageServer(w http.ResponseWriter, cookie *http.Cookie) {
	home, err := os.ReadFile("./static/home.html")
	if err != nil {
		log.Println("error while reading home.html: ", err)
		http.Error(w, "error while reading home file", http.StatusInternalServerError)
		return
	}
	user := getUserBySessionID(cookie.Value)
	log.Printf("successfully served home page for user: %v\n", user.Username)
	w.Write([]byte(home))
}

////////////////////////////////
// other functions
////////////////////////////////

// Random SessionID generator
func getCustomID() string {
	currentTime := time.Now().UnixNano()
	uniqueID := uuid.New()
	return fmt.Sprintf("%d-%s", currentTime, uniqueID)
}

// convert string to BoolInt
func stringToBoolInt(s string) BoolInt {
	s = strings.ToLower(s)
	if s == "true" || s == "1" {
		return True
	}
	return False
}

func maskPasswords(users []User) []User {
	for i := range users {
		users[i].Password = "********"
	}
	return users

}
