package main

import (
	"log"

	"github.com/argoproj/argo-cd/v2/util/glob"
	"github.com/casbin/casbin/v2"
)

func check(err error) {
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// Glob match func
func globMatchFunc(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return false, nil
	}
	val, ok := args[0].(string)
	if !ok {
		return false, nil
	}

	pattern, ok := args[1].(string)
	if !ok {
		return false, nil
	}

	return glob.Match(pattern, val), nil
}

func main() {
	e, err := casbin.NewEnforcer("argo-cd-model.conf", "argo-cd-builtin-policy.csv")
	check(err)

	e.AddFunction("globOrRegexMatch", globMatchFunc)

	allSubjects := e.GetAllSubjects()
	log.Println(allSubjects)

	groupingPolicy := e.GetGroupingPolicy()
	log.Println(groupingPolicy)

	ok, err := e.Enforce("admin", "applications", "get", "foo/bar")
	check(err)
	log.Printf("Result: %v", ok)
}
