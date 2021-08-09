package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

type Class struct {
	Id        int
	ClassName string
	Teacher   int
}
type admClass struct {
	Class []Class
}

func getClass(id string) []Class {
	s := "SELECT * FROM class WHERE teacher = " + id
	rows, err := database.Query(s)
	if err != nil {
		log.Println(err)
	}
	defer rows.Close()
	class := []Class{}
	for rows.Next() {
		p := Class{}
		err := rows.Scan(&p.Id, &p.ClassName, &p.Teacher)
		if err != nil {
			fmt.Println(err)
			continue
		}
		class = append(class, p)
	}
	return class
}

func AdmStudents(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		fmt.Println("POST")
	} else {
		wp := admClass{}
		wp.Class = getClass(strconv.Itoa(CurUser.Id))
		tmpl := template.Must(template.ParseFiles("./html/admStudent.html"))
		tmpl.Execute(w, wp)
	}
}
