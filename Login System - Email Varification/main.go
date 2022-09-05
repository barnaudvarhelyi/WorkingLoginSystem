//idea and solution: https://www.youtube.com/watch?v=djU1_308M8E&ab_channel=GrowAdept
//https://github.com/GrowAdept/youtube/blob/main/gin/

package main

import (
	"bufio"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	// "github.com/gin-gonic/gin"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	emailverifier "github.com/AfterShip/email-verifier"
)

const minEntropyBits = 60

var (
	verifier = emailverifier.NewVerifier()
	store    = sessions.NewCookieStore([]byte("super-secret"))
	tpl      *template.Template
)

func init() {
	verifier = verifier.EnableDomainSuggest()

	// if servLog == "remote" {
	// }
	verifier = verifier.EnableSMTPCheck()
	dispEmailsDomains := MustDispEmailDom()
	verifier = verifier.AddDisposableDomains(dispEmailsDomains)
}

func main() {
	var err error
	tpl, err = template.ParseGlob("../pages/*.html")
	if err != nil {
		fmt.Println(err)
	}

	// router := gin.Default()
	// router.LoadHTMLGlob("../Webpages/*.html")
	// router.GET("/", indexHandler)
	// router.GET("/login", loginGetHandler)
	// router.POST("/login", loginPostHandler)
	// router.GET("/logout", logoutGetHandler)
	// router.GET("/register", registerGetHandler)
	// router.POST("/register", registerPostHandler)
	// router.GET("/emailver/:username/:verPass", emailverGetHandler)
	// router.GET("/home", homeGetHandler)
	// router.GET("/account/profile", Auth(accProfileHandler))
	// router.GET("/account/edit", Auth(accProfileEditPostHandler))
	// router.GET("/account/edit/verify", Auth(accEditVerGetHandler))
	//  router.Run("localhost:8080")

	mux := mux.NewRouter()

	header := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization", "X-Content-Type-Options"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PATCH", "DELETE", "PUT", "HEAD", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/home", homeHandler)

	mux.HandleFunc("/login", loginHandler)

	mux.HandleFunc("/logout", logoutHandler)

	mux.HandleFunc("/register", registerHandler)

	mux.HandleFunc("/emailver/{username}/{verPass}", emailVerHandler)

	mux.HandleFunc("/account/profile", accProfileHandler)
	mux.HandleFunc("/account/edit", accProfileEditHandler)
	mux.HandleFunc("/account/edit/verify", accEditVerHandler)

	mux.HandleFunc("/forgotpsw", forgotPswHandler)
	mux.HandleFunc("/forgotpswval", forgotPswValHandler)
	mux.HandleFunc("/forgotpswemailver", forgotPswEmailVerHandler)
	mux.HandleFunc("/forgotpswchange", forgotPswChangeHandler)

	err = http.ListenAndServe(ListenAndServeIp, handlers.CORS(header, methods, origins)(mux))
	if err != nil {
		log.Fatal(err)
	}
}

//list from https://github.com/disposable-email-domains/disposable-email-domains/blob/master/disposable_email_blocklist.conf
func MustDispEmailDom() (dispEmailsDomains []string) {
	file, err := os.Open("../disposable_email_blocklist.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		dispEmailsDomains = append(dispEmailsDomains, scanner.Text())
	}
	return dispEmailsDomains
}

func AuthMiddleware(HandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		_, ok := session.Values["userId"]
		if !ok {
			fmt.Println(err)
			http.Redirect(w, r, "/login", 302)
			return
		}
		HandlerFunc.ServeHTTP(w, r)
	}
}
