package mongodb

import (
	"fmt"
	"slices"

	"go.mongodb.org/mongo-driver/bson"
)

// UnmarshalBSON preserves field presence because an empty bucket suffix means
// all time-series buckets. Explicit zero-valued mixed fields are not aliases
// for that resource and must not disappear while decoding rolesInfo.
func (resource *roleResource) UnmarshalBSON(data []byte) error {
	elements, err := bson.Raw(data).Elements()
	if err != nil {
		return err
	}
	fields := make(map[string]bool, len(elements))
	for _, element := range elements {
		if fields[element.Key()] {
			return fmt.Errorf("duplicate MongoDB resource field %q", element.Key())
		}
		fields[element.Key()] = true
	}
	if fields["system_buckets"] {
		for _, element := range elements {
			if (element.Key() == "system_buckets" || element.Key() == "db") && element.Value().Type != bson.TypeString {
				// The generic string codec coerces BSON Symbol and Binary values.
				// A coerced empty suffix would authorize the all-buckets resource.
				return fmt.Errorf("MongoDB bucket resource field %q must be a BSON string", element.Key())
			}
		}
	}
	type plainResource roleResource
	var decoded plainResource
	if err := bson.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*resource = roleResource(decoded)
	resource.observedFields = fields
	return nil
}

func (resource roleResource) hasSystemBuckets() bool {
	return resource.SystemBuckets != nil || resource.observedFields["system_buckets"]
}

// Only the two emitted all-buckets shapes are supported by observation. The
// API's desired role-document grammar remains unchanged. Other bucket suffix
// forms, unknown keys and combinations with normal/cluster scopes fail closed.
func validObservedSystemBuckets(resource roleResource) bool {
	if resource.SystemBuckets == nil || *resource.SystemBuckets != "" ||
		resource.Collection != "" || resource.Cluster || resource.AnyResource {
		return false
	}
	for _, key := range []string{"collection", "cluster", "anyResource"} {
		if resource.observedFields[key] {
			return false
		}
	}
	// The global serializer omits db; a present db denotes a specific database.
	return !resource.observedFields["db"] || resource.DB != ""
}

func observedSystemBucketsKey(resource roleResource) string {
	suffix := "null"
	if resource.SystemBuckets != nil {
		suffix = fmt.Sprintf("string:%q", *resource.SystemBuckets)
	}
	mixed := make([]string, 0)
	for _, key := range []string{"collection", "cluster", "anyResource"} {
		if resource.observedFields[key] {
			mixed = append(mixed, key)
		}
	}
	slices.Sort(mixed)
	return fmt.Sprintf("system_buckets|db=%q|suffix=%s|collection=%q|cluster=%t|any=%t|empty_db_field=%t|mixed=%q",
		resource.DB, suffix, resource.Collection, resource.Cluster, resource.AnyResource,
		resource.observedFields["db"] && resource.DB == "", mixed)
}

func printableObservedResourceKey(resource roleResource) string {
	if resource.hasSystemBuckets() {
		return observedSystemBucketsKey(resource)
	}
	return printableResourceKey(typedRoleResource(resource))
}

func observedPrivilegeToken(resource roleResource, action string, effective bool) string {
	kind := "privilege:"
	if effective {
		kind = "effective_privilege:"
	}
	return kind + printableObservedResourceKey(resource) + ":" + action
}
