package main

import (
	"log"

	"github.com/argoproj/argo-cd/v2/util/glob"
	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
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
	adapter := fileadapter.NewAdapter("argo-cd-builtin-policy.csv")
	e, err := casbin.NewEnforcer("argo-cd-model.conf", adapter)
	check(err)

	e.AddFunction("globOrRegexMatch", globMatchFunc)

	allSubjects := e.GetAllSubjects()
	log.Println("--> GetAllSubjects()")
	log.Println(allSubjects)

	groupingPolicy := e.GetGroupingPolicy()
	log.Println("--> GetGroupingPolicy()")
	log.Println(groupingPolicy)

	domains, err := e.GetAllDomains()
	check(err)
	log.Println("--> GetAllDomains()")
	log.Println(domains)

	allPolicies := e.GetPolicy()
	log.Println("--> GetPolicy()")
	log.Println(allPolicies)

	allUsersForDomain1 := e.GetAllUsersByDomain("domain1")
	log.Println("--> GetAllUsersByDomain()")
	log.Println(allUsersForDomain1)

	ok, err := e.Enforce("admin", "domain1", "applications", "get", "foo/bar")
	check(err)
	log.Printf("Result: %v", ok)
}
