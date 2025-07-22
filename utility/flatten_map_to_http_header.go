package utility

import (
	"fmt"
	"reflect"
	"strconv"
)

func FlattenMapToHttpHeader(in map[string]interface{}, prefix string) map[string][]string {
	return flattenMapToHttpHeader(map[string][]string{}, prefix, reflect.ValueOf(in))
}

func flattenMapToHttpHeader(in map[string][]string, k string, v reflect.Value) map[string][]string {
	concatString := func(a, b string) string {
		if a == "" {
			return b
		}
		return a + "-" + b
	}
	mergeMap := func(maps ...map[string][]string) map[string][]string {
		c := make(map[string][]string)
		for _, m := range maps {
			for k, v := range m {
				if _, ok := m[k]; ok {
					c[k] = v
				}
			}
		}
		return c
	}

	var value []string
	if val, exist := in[k]; exist {
		value = val
	} else {
		value = []string{}
	}

	switch v.Kind() {
	case reflect.Bool:
		if v.Interface().(bool) {
			in[k] = append(value, "true")
		} else {
			in[k] = append(value, "false")
		}
		return in
	case reflect.Int:
		in[k] = append(value, strconv.Itoa(v.Interface().(int)))
		return in
	case reflect.Float64:
		in[k] = append(value, strconv.FormatFloat(v.Interface().(float64), 'f', 0, 64))
		return in
	case reflect.String:
		in[k] = append(value, v.Interface().(string))
		return in
	case reflect.Slice:
		for _, value := range v.Interface().([]interface{}) {
			in = mergeMap(in, flattenMapToHttpHeader(in, k, reflect.ValueOf(value)))
		}
		return in
	case reflect.Map:
		for _, e := range v.MapKeys() {
			in = mergeMap(in, flattenMapToHttpHeader(in, concatString(k, e.String()), reflect.ValueOf(v.MapIndex(e).Interface())))
		}
		return in
	default:
		fmt.Println(k, v, v.Kind(), "undefined")
		return in
	}
}
