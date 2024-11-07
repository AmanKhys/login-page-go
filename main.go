package main

import (
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"math/rand"
	"net/http"
	"strconv"
)

var (
	ErrValueTooLong        = errors.New("cookie value too long")
	ErrInvalidValue        = errors.New("cookie value is invalid")
	ErrCookieAlreadyExists = errors.New("cookie already exists.")

	db *sql.DB
)

type User struct {
	id        int
	username  string
	password  string
	sessionid int
}

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
	row := db.QueryRow("select * from users;")

	var id, sessionid int
	var username, password string
	err := row.Scan(&id, &username, &password, &sessionid)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Id: %d, Username: %s, Password: %s, SessionID: %d\n", id, username, password, sessionid)
	}

	// backend logic
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Print("Listenting on: 4444...")
	err = http.ListenAndServe(":4444", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func getUsers(db *sql.DB) []User {
	var users []User
	rows, err := db.Query("select * from users;")
	if err != nil {
		log.Println("cannot take row from db users", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(&user.id, &user.username, &user.password, &user.sessionid)
		if err != nil {
			log.Println(err)
			break
		}
		users = append(users, user)
	}
	return users
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "sessionid")
	if cookie == nil {
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if err != nil {
		log.Println(err)
		http.ServeFile(w, r, "./static/index.html")
		return
	}
	if checkSession(cookie.Value) {
		http.ServeFile(w, r, "./static/home.html")
		return
	}
	http.ServeFile(w, r, "./static/index.html")
}

func checkSession(sessionidStr string) bool {
	var users []User
	var ids []int
	fmt.Println("ids: ", ids)
	id, err := strconv.Atoi(sessionidStr)
	if err != nil {
		log.Println("unable to convert sessionid to int to check whether sessionid exists in db.", err)
		return false
	}
	fmt.Printf("cookie sessionid: %d\n", id)
	users = getUsers(db)

	for _, user := range users {
		ids = append(ids, user.sessionid)
	}

	for i := 0; i < len(ids); i++ {
		fmt.Printf("id == ids[%d]; %d == %d\n", i, id, ids[i])
		if id == ids[i] {
			return true
		}
	}

	return false
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var users = getUsers(db)
	fmt.Println(users)
	var sessionid int
	var rUser, rPassword string = r.FormValue("username"), r.FormValue("password")
	fmt.Printf("ruser: %s, rpw:  %s\n", rUser, rPassword)
	var flag bool
	for _, user := range users {
		if rUser == user.username && rPassword == user.password {
			flag = true
			sessionid = rand.Intn(9000) + 1000
			query := "update users set sessionid = ? where id = ?;"
			_, err := db.Exec(query, sessionid, user.id)
			if err != nil {
				log.Printf("unable to update sessionid: %d for id: %d\n%v", sessionid, user.id, err)
			}
		} else if rUser == user.username && rPassword != user.password {
			http.Error(w, "entered incorrect password", http.StatusBadRequest)
		}
	}
	if flag {
		writeCookie(w, sessionid)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := readCookie(r, "sessionid")
	if err == ErrInvalidValue {
		http.Error(w, "cookie has been alterned/changed without permission.", http.StatusBadRequest)
		return
	} else if err == ErrCookieAlreadyExists {
		log.Println("Cookie already exists... updating cookie maxage.")
	}
	cookie.Value = "false"
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func writeCookie(w http.ResponseWriter, sessionid int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sessionid",
		Value:    strconv.Itoa(sessionid),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	// read the cookie as normal
	cookie, err := r.Cookie(name)
	if err != nil {
		log.Println("unabel to read the cookie.")
		return nil, http.ErrNoCookie
	}
	value, err := strconv.Atoi(cookie.Value)
	if err != nil {
		log.Println("failed to convert from string to integer of the sessionid field from request cookie.")
	}

	if cookie == nil {
		return nil, errors.New("cookie dose not exist")
	} else if value < 1000 && value > 9999 {
		return nil, ErrInvalidValue
	} else if cookie.MaxAge > 0 {
		return nil, ErrCookieAlreadyExists
	} else if err != nil {
		return nil, err
	}
	return cookie, nil
}
