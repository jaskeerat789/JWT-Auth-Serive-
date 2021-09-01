package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-hclog"
)

var port = os.Getenv("PORT")

func main() {
	l := hclog.New(&hclog.LoggerOptions{Name: "Main"})

	sm := mux.NewRouter()

	handlers.CORS(handlers.AllowedHeaders([]string{"http://localhost:" + port}))

	authHandler := NewAuth()

	sm.HandleFunc("/login", authHandler.Login).Methods("POST")
	sm.Handle("/ping", authHandler.AuthMiddleware(http.HandlerFunc(authHandler.Ping))).Methods("GET")

	s := &http.Server{
		Addr:         ":" + port,
		Handler:      sm,
		ErrorLog:     l.StandardLogger(&hclog.StandardLoggerOptions{}),
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	go func() {
		l.Info("Starting server...", "port", port)
		err := s.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt)
	signal.Notify(sigChan, os.Kill)

	sig := <-sigChan
	l.Info("Received terminate, graceful shutdown", sig)

	tc, _ := context.WithTimeout(context.Background(), 30*time.Second)
	s.Shutdown(tc)

}
