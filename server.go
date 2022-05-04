package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"

	//	stud "github.com/server/students"
	"golang.org/x/crypto/scrypt"
)

type Token struct {
	Role int
	Id   int
	jwt.StandardClaims
}
type Account struct {
	User  User
	Token string `json:"token"`
}

type neuteredFileSystem struct {
	fs http.FileSystem
}
type htmlform map[string]string

type AdmTopic struct {
	Topic Topic
	Word  []string
	HForm []string
}

type User struct {
	Id           int
	Username     string
	Role         int
	Class        int
	Userpassword []byte
}

type Topic struct {
	Id       int
	Name     string
	FormName string
	Count    int
	Ch1      string
	Ch2      string
	Ch3      string
}
type Word struct {
	Id   int
	Word string
}

const lenPath = len("/adm/")

var database *sql.DB
var htmlf htmlform
var hform []string
var salt []byte
var CurUser User
var account = &Account{}

func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if s.IsDir() {
		index := filepath.Join(path, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, err
		}
	}
	return f, nil
}

func readjson() (htmlform, []string) {
	plan, _ := ioutil.ReadFile("./form.json") // filename is the JSON file to read
	var data htmlform
	var datas []string
	err := json.Unmarshal(plan, &data)
	if err != nil {
		fmt.Println(err)
	}
	for key := range data {
		datas = append(datas, key)
	}
	return data, datas
}

func getUser(name string, psw string) (User, bool) {
	s := "SELECT * FROM users WHERE username = '" + name + "'"
	rows, err := database.Query(s)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	p := User{}
	for rows.Next() {
		err := rows.Scan(&p.Id, &p.Username, &p.Role, &p.Class, &p.Userpassword)
		if err != nil {
			fmt.Println(err)
			return p, false
		}
	}
	getpsw, _ := scrypt.Key([]byte(psw), salt, 16384, 8, 1, 32)
	//	_, e := database.Exec("update users set userpassword = $2 where username = $1", p.Username, string(getpsw))

	if string(getpsw) == string(p.Userpassword) {
		return p, true

	}
	return p, false
}

func addCookie(w http.ResponseWriter, value string, ttl time.Duration) {
	cookie := http.Cookie{
		Name:     "login",
		Value:    value,
		HttpOnly: true,
		Expires:  time.Now().Add(ttl),
	}
	fmt.Println(cookie)
	http.SetCookie(w, &cookie)
}

func start(w http.ResponseWriter, r *http.Request) {
	//	account := &Account{}
	if r.Method == "POST" {
		addCookie(w, "", -30*time.Minute)
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
		}
		name := r.FormValue("uname")
		psw := r.FormValue("psw")
		find := false
		CurUser, find = getUser(name, psw)
		//		fmt.Println("Код")

		//		fmt.Println(CurUser.Id)
		if find && CurUser.Role == 1 {

			tk := &Token{Role: CurUser.Role, Id: CurUser.Id}
			token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
			tokenString, _ := token.SignedString([]byte("token_password"))

			account.Token = tokenString
			account.User = CurUser
			account.User.Userpassword = nil
			account.User.Username = ""
			addCookie(w, tokenString, 60*time.Minute)
			//	resp := map[string]interface{}{"account": account}
			//	Respond(w, resp)
		}
	} else {
		account.Token = ""
		account.User = CurUser
	}

	tmpl := template.Must(template.ParseFiles("./html/start.html"))
	tmpl.Execute(w, account)
}

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}
func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := make(map[string]interface{})
		//	tokenHeader := r.Header.Get("Cookie") //Получение токена
		val, _ := r.Cookie("login")
		tokenHeader := val.Value
		if tokenHeader == "" { //Токен отсутствует, возвращаем  403 http-код Unauthorized
			response = Message(false, "Missing auth token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		tk := &Token{}
		token, err := jwt.ParseWithClaims(tokenHeader, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte("token_password"), nil
		})

		if err != nil { //Неправильный токен, как правило, возвращает 403 http-код
			response = Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		if !token.Valid { //токен недействителен, возможно, не подписан на этом сервере
			response = Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			Respond(w, response)
			return
		}

		//Всё прошло хорошо, продолжаем выполнение запроса
		fmt.Println("Role %", tk.Role) //Полезно для мониторинга
		ctx := context.WithValue(r.Context(), "role", tk.Role)
		CurUser.Id = tk.Id
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Println("$PORT must be set")
	}
	//	log.Println(os.Getenv("DATABASE_URL"))
	CurUser = User{0, "", 0, 0, nil}
	db, er := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if er != nil {
		log.Println(er)
	}
	database = db
	defer db.Close()
	htmlf, hform = readjson()
	salt = []byte("asdfasdf")
	finalHandler := http.HandlerFunc(adm)
	mux := http.NewServeMux()
	mux.HandleFunc("/", start)
	mux.HandleFunc("/menu", menu)
	mux.HandleFunc("/menu/", home)
	mux.Handle("/adm", checkToken(finalHandler))
	mux.Handle("/students", checkToken(http.HandlerFunc(AdmStudents)))
	mux.Handle("/adm/", checkToken(http.HandlerFunc(admTopic)))

	fileServer := http.FileServer(neuteredFileSystem{http.Dir("./html/css/")})
	mux.Handle("/static", http.NotFoundHandler())

	//	fileServer := http.FileServer(http.Dir("./html/css/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	// Используется функция http.ListenAndServe() для запуска нового веб-сервера.
	log.Println("Запуск веб-сервера на :", port)
	err := http.ListenAndServe(":"+port, mux)
	log.Fatal(err)
}
