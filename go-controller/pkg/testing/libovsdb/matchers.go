package libovsdb

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"

	"github.com/mitchellh/copystructure"
	"github.com/onsi/gomega"
	gomegaformat "github.com/onsi/gomega/format"
	gomegatypes "github.com/onsi/gomega/types"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
)

var validUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isStringSetEqual(x, y interface{}) bool {
	xs, ok := x.([]string)
	if !ok {
		return false
	}
	ys, ok := y.([]string)
	if !ok {
		return false
	}
	if len(xs) != len(ys) {
		return false
	}
	xsc := make([]string, len(xs))
	ysc := make([]string, len(ys))
	copy(xsc, xs)
	copy(ysc, ys)
	sort.Strings(xsc)
	sort.Strings(ysc)
	return reflect.DeepEqual(xsc, ysc)
}

func isUUIDSlice(x interface{}) bool {
	xs, ok := x.([]string)
	if !ok {
		return false
	}
	for _, e := range xs {
		if !validUUID.MatchString(e) {
			return false
		}
	}
	return true
}

func isUUIDMap(x interface{}) bool {
	m, ok := x.(map[string]string)
	if !ok {
		return false
	}
	ks := make([]string, 0, len(m))
	vs := make([]string, 0, len(m))
	for k, v := range m {
		ks = append(ks, k)
		vs = append(vs, v)
	}
	return isUUIDSlice(ks) || isUUIDSlice(vs)
}

// replaceUUIDs replaces atomic, slice or map strings from the mapping
// function provided
func replaceUUIDs(data TestData, mapFrom func(string, int) string) {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		return
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return
	}
	for i, n := 0, v.NumField(); i < n; i++ {
		f := v.Field(i).Interface()
		switch f.(type) {
		case string:
			s := f.(string)
			v.Field(i).Set(reflect.ValueOf(mapFrom(s, i)))
		case []string:
			s := f.([]string)
			for si, sv := range s {
				s[si] = mapFrom(sv, i)
			}
		case map[string]string:
			m := f.(map[string]string)
			for mk, mv := range m {
				nv := mapFrom(mv, i)
				nk := mapFrom(mk, i)
				m[nk] = nv
				if nk != mk {
					delete(m, mk)
				}
			}
		}
	}
}

// replaceNamedUUIDs replaces UUIDs both in actual and expected
// combining actual UUIDs found in actual with named UUIDs
// found in expected.
func replaceNamedUUIDs(actual, expected []TestData) {
	names := map[string]string{}
	uuids := map[string]string{}
	expectedToActual := map[int]int{}
	actualFieldsReplaced := map[[2]int]bool{}
	for i, x := range actual {
		for j, y := range expected {
			if !testDataEqual(x, y, true) {
				continue
			}
			uuid := getUUID(x)
			name := getUUID(y)
			fname := names[uuid]
			if fname != "" {
				panic(fmt.Sprintf("Can't infer named UUIDs, found multiple matches: [%s -> %s, %s]", uuid, name, fname))
			}
			names[uuid] = name
			uuids[name] = uuid
			expectedToActual[j]=i
			break
		}
	}
	for i, x := range actual {
		replaceUUIDs(x, func(uuid string, field int) string {
			name, ok := names[uuid]
			if !ok {
				return uuid
			}
			actualFieldsReplaced[[2]int{i, field}] = true
			return fmt.Sprintf("%s [%s]", uuid, name)
		})
	}
	// on expected, only replace fields that were replaced in actual
	for j, y := range expected {
		replaceUUIDs(y, func(name string, field int) string {
			uuid, ok := uuids[name]
			if !ok {
				return name
			}
			i, ok := expectedToActual[j]
			if !ok {
				return name
			}
			replaced := actualFieldsReplaced[[2]int{i, field}]
			if !replaced {
				return name
			}
			return fmt.Sprintf("%s [%s]", uuid, name)
		})
	}
}

func getUUID(x TestData) string {
	v := reflect.ValueOf(x)
	if v.Kind() != reflect.Ptr {
		return ""
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return ""
	}
	for i, n := 0, v.NumField(); i < n; i++ {
		if tag := v.Type().Field(i).Tag.Get("ovsdb"); tag == "_uuid" {
			return v.Field(i).String()
		}
	}
	return ""
}

// testDataEqual tests for equality assuming input libovsdb models, as follows:
// - Expects input to be pointers to struct
// - If ignoreUUIDs, UUIDs are ignored from string, slice or map members of the struct
// - Members of the struct that are string slices are compared as an unordered set
// - Otherwise reflect.DeepEqual is used.
func testDataEqual(x, y TestData, ignoreUUIDs bool) bool {
	if x == nil || y == nil {
		return x == y
	}
	v1 := reflect.ValueOf(x)
	v2 := reflect.ValueOf(y)
	if !v1.IsValid() || !v2.IsValid() {
		return v1.IsValid() == v2.IsValid()
	}
	if v1.Type() != v2.Type() {
		return false
	}
	if v1.Kind() != reflect.Ptr {
		return false
	}
	v1 = v1.Elem()
	v2 = v2.Elem()
	if v1.Kind() != reflect.Struct {
		return false
	}
	for i, n := 0, v1.NumField(); i < n; i++ {
		if tag := v1.Type().Field(i).Tag.Get("ovsdb"); tag == "" || (tag == "_uuid" && ignoreUUIDs) {
			continue
		}
		f1 := v1.Field(i)
		f2 := v2.Field(i)
		switch f1.Kind() {
		case reflect.String:
			if ignoreUUIDs {
				isF1UUID := validUUID.MatchString(f1.String())
				isF2UUID := validUUID.MatchString(f2.String())
				if isF1UUID || isF2UUID {
					continue
				}
			}
		case reflect.Slice:
			if ignoreUUIDs {
				if f1.Len() != f2.Len() {
					return false
				}
				isF1UUIDSlice := isUUIDSlice(f1.Interface())
				isF2UUIDSlice := isUUIDSlice(f2.Interface())
				if isF1UUIDSlice || isF2UUIDSlice {
					continue
				}
			}
			if !isStringSetEqual(f1.Interface(), f2.Interface()) {
				return false
			}
			continue
		case reflect.Map:
			if ignoreUUIDs {
				if f1.Len() != f2.Len() {
					return false
				}
				isF1UUIDMap := isUUIDMap(f1.Interface())
				isF2UUIDMap := isUUIDMap(f2.Interface())
				if isF1UUIDMap || isF2UUIDMap {
					continue
				}
			}
		}
		if !reflect.DeepEqual(f1.Interface(), f2.Interface()) {
			return false
		}
	}
	return true
}

// HaveTestData matches expected libovsdb models with named UUIDs
func HaveTestData(expected ...TestData) gomegatypes.GomegaMatcher {
	return haveTestData(false, true, expected)
}

// HaveTestDataIgnoringUUIDs matches expected libovsdb models ignoring UUIDs
func HaveTestDataIgnoringUUIDs(expected ...TestData) gomegatypes.GomegaMatcher {
	return haveTestData(true, false, expected)
}

// HaveTestDataExact matches expected libovsdb models exactly
func HaveTestDataExact(expected ...TestData) gomegatypes.GomegaMatcher {
	return haveTestData(false, false, expected)
}

func HaveEmptyTestData() gomegatypes.GomegaMatcher {
	transform := func(client libovsdbclient.Client) []TestData {
		return getTestDataFromClientCache(client)
	}
	return gomega.WithTransform(transform, gomega.BeEmpty())
}

func haveTestData(ignoreUUIDs, nameUUIDs bool, expected []TestData) gomegatypes.GomegaMatcher {
	if e, ok := expected[0].([]TestData); len(expected) == 1 && ok {
		// flatten
		expected = e
	}
	matchers := []*testDataMatcher{}
	for _, e := range expected {
		matchers = append(matchers, matchTestData(ignoreUUIDs, e))
	}
	transform := func(client libovsdbclient.Client) []TestData {
		actual := getTestDataFromClientCache(client)
		if nameUUIDs {
			expectedCopy := copystructure.Must(copystructure.Copy(expected)).([]TestData)
			actualCopy := copystructure.Must(copystructure.Copy(actual)).([]TestData)
			replaceNamedUUIDs(actualCopy, expectedCopy)
			for i, m := range matchers {
				m.expected = expectedCopy[i]
			}
			return actualCopy
		}
		return actual
	}
	return gomega.WithTransform(transform, gomega.ContainElements(matchers))
}

func matchTestData(ignoreUUID bool, expected TestData) *testDataMatcher {
	return &testDataMatcher{
		expected:   expected,
		ignoreUUID: ignoreUUID,
	}
}

type testDataMatcher struct {
	expected   TestData
	ignoreUUID bool
}

func (matcher *testDataMatcher) Match(actual interface{}) (bool, error) {
	data, ok := actual.(TestData)
	if !ok {
		return false, fmt.Errorf("MatchServerData matcher expects a libovsdb.TestData")
	}
	return testDataEqual(data, matcher.expected, matcher.ignoreUUID), nil
}

func (matcher *testDataMatcher) FailureMessage(actual interface{}) string {
	return gomegaformat.Message(actual, "to equal", matcher.expected)
}

func (matcher *testDataMatcher) NegatedFailureMessage(actual interface{}) string {
	return gomegaformat.Message(actual, "not to equal", matcher.expected)
}
