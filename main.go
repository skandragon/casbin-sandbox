package main

import (
	"log"

	"github.com/gobwas/glob"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

const (
	modelFile  = "argo-cd-model.conf"
	policyFile = "argo-cd-builtin-policy.csv"
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

	return Match(pattern, val), nil
}

func Match(pattern, text string, separators ...rune) bool {
	compiledGlob, err := glob.Compile(pattern, separators...)
	if err != nil {
		log.Printf("failed to compile pattern %s due to error %v", pattern, err)
		return false
	}
	return compiledGlob.Match(text)
}

func main() {
	a := fileadapter.NewFilteredAdapter(policyFile)

	m, err := model.NewModelFromFile(modelFile)
	check(err)

	e, err := casbin.NewEnforcer(m, a)
	check(err)

	e.AddFunction("globOrRegexMatch", globMatchFunc)

	// Sample filter which only loads one domain.
	domain1 := "domain1"
	f := fileadapter.Filter{
		P: []string{"", domain1},
		G: []string{"", "", domain1},
	}

	err = e.LoadFilteredPolicy(&f)
	check(err)

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
