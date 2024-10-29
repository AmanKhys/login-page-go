package main

import (
	"log"
	"net/http"
)

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	log.Print("Listenting on: 4444...")
	err := http.ListenAndServe(":4444", nil)
	if err != nil {
		log.Fatal(err)
	}
}
