// Package env provides a convenient way to convert environment
// variables into Go data.
package env

import (
	"encoding/base64"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Int returns the value of the named environment variable,
// interpreted as an int (using strconv.Atoi).
// If there is an error parsing the value, it prints a
// diagnostic message to the log and calls os.Exit(1).
// If name isn't in the environment, it returns value.
func Int(name string, value int) int {
	if s := os.Getenv(name); s != "" {
		var err error
		value, err = strconv.Atoi(s)
		if err != nil {
			log.Println(name, err)
			os.Exit(1)
		}
	}
	return value
}

// Bool returns the value of the named environment variable,
// interpreted as a bool (using strconv.ParseBool).
// If there is an error parsing the value, it prints a
// diagnostic message to the log and calls os.Exit(1).
// If name isn't in the environment, it returns value.
func Bool(name string, value bool) bool {
	if s := os.Getenv(name); s != "" {
		var err error
		value, err = strconv.ParseBool(s)
		if err != nil {
			log.Println(name, err)
			os.Exit(1)
		}
	}
	return value
}

// Bytes returns the value of the named environment variable,
// interpreted as a base64 string (using base64.StdEncoding).
// If there is an error parsing the value, it prints a
// diagnostic message to the log and calls os.Exit(1).
// If name isn't in the environment, it returns value.
func Bytes(name string, value []byte) []byte {
	if s := os.Getenv(name); s != "" {
		var err error
		value, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			log.Println(name, err)
			os.Exit(1)
		}
	}
	return value
}

// Duration returns the value of the named environment variable,
// interpreted as a time.Duration (using time.ParseDuration).
// If there is an error parsing the value, it prints a
// diagnostic message to the log and calls os.Exit(1).
// If name isn't in the environment, it returns value.
func Duration(name string, value time.Duration) time.Duration {
	if s := os.Getenv(name); s != "" {
		var err error
		value, err = time.ParseDuration(s)
		if err != nil {
			log.Println(name, err)
			os.Exit(1)
		}
	}
	return value
}

// URL returns the value of the named environment variable,
// interpreted as a *url.URL (using url.Parse).
// If there is an error parsing the environment value, it prints a
// diagnostic message to the log and calls os.Exit(1).
// If name isn't in the environment, URL returns the *url.URL
// that results from parsing the given value.
// URL panics if there is an error parsing the given value.
func URL(name string, value string) *url.URL {
	v, err := url.Parse(value)
	if err != nil {
		panic(err)
	}
	if s := os.Getenv(name); s != "" {
		v, err = url.Parse(s)
		if err != nil {
			log.Println(name, err)
			os.Exit(1)
		}
	}
	return v
}

// String returns the value of the named environment variable.
// If name isn't in the environment or is empty, it returns value.
func String(name string, value string) string {
	if s := os.Getenv(name); s != "" {
		value = s
	}
	return value
}

// LookupString returns the value of the named environment variable.
// If name isn't in the environment, it returns value.
func LookupString(name, value string) string {
	s, ok := os.LookupEnv(name)
	if ok {
		value = s
	}
	return value

}

// StringSlice returns the value of the named environment variable,
// interpreted as []string (using strings.Split with ",").
// If name isn't in the environment or is empty, it returns value.
func StringSlice(name string, value ...string) []string {
	if s := os.Getenv(name); s != "" {
		a := strings.Split(s, ",")
		value = a
	}
	return value
}

// LookupStringSlice returns the value of the named environment variable,
// interpreted as []string (using strings.Split with ",").
// If name isn't in the environment, it returns value.
func LookupStringSlice(name string, value ...string) []string {
	s, ok := os.LookupEnv(name)
	if ok {
		a := strings.Split(s, ",")
		value = a
	}
	return value

}
