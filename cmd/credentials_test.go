package cmd

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}

func TestValidSelectorParsing(t *testing.T) {
	fixtures := []string{
		"file://../tst/selectors/valid-all-attributes-selector.json",
		"file://../tst/selectors/valid-some-attributes-selector.json",
		"Key=x509Subject,Value=CN=Subject Key=x509Issuer,Value=CN=Issuer Key=x509Serial,Value=15D19632234BF759A32802C0DA88F9E8AFC8702D",
		"Key=x509Subject,Value=CN=CN With Spaces Key=x509Issuer,Value=CN=CN With Spaces,OU=OU With Spaces",
		"Key=x509Subject,Value=CN=CN With Spaces,O=O With Spaces Key=x509Issuer,Value=CN=Issuer",
		" \n  Key=x509Subject,Value=CN=CN With Spaces,O=O With Spaces   \t   Key=x509Issuer,Value=CN=Issuer  \n",
		"Key=x509Issuer,Value=CN=Issuer",
	}
	for _, fixture := range fixtures {
		_, err := PopulateCertIdentifier(fixture, "MY")
		if err != nil {
			t.Log("Unable to populate cert identifier from selector")
			t.Fail()
		}
	}
}

func TestInvalidSelectorParsing(t *testing.T) {
	fixtures := []string{
		"file://../tst/selectors/invalid-selector.json",
		"file://../tst/selectors/invalid-selector-2.json",
		"file://../tst/selectors/invalid-selector-3.json",
		"laksdjadf",
		"Key=laksdjf,Valalsd",
		"Key=aljsdf,Value=aljsdfadsf",
		"asdf Key=x509Subject,Value=Test",
	}
	for _, fixture := range fixtures {
		_, err := PopulateCertIdentifier(fixture, "MY")
		if err == nil {
			t.Log("Expected parsing failure, but received none")
			t.Fail()
		}
	}
}
