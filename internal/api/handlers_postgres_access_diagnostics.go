package api

import (
	"cmp"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

const postgresDiagnosticEvidenceLimit = 2000
const postgresDiagnosticFindingLimit = 100

type postgresAccessSource struct {
	Kind       string `json:"kind"`
	Role       string `json:"role,omitempty"`
	Activation string `json:"activation"`
}

type postgresAccessFinding struct {
	Resource          string               `json:"resource"`
	ObjectKind        string               `json:"object_kind"`
	Privilege         string               `json:"privilege"`
	Source            postgresAccessSource `json:"source"`
	GrantOption       bool                 `json:"grant_option,omitempty"`
	Grantors          []string             `json:"grantors,omitempty"`
	GrantorsTruncated bool                 `json:"grantors_truncated,omitempty"`
}

type postgresDiagnosticResource struct {
	ID         uuid.UUID
	Kind       string
	Path       string
	Attributes json.RawMessage
}

type postgresDiagnosticGrant struct {
	Subject           string
	ResourceID        uuid.UUID
	Attributes        json.RawMessage
	BindingAttributes json.RawMessage
}

type postgresDiagnosticTopology struct {
	Evidence       adapter.PostgresAccessEvidence `json:"postgres_access_evidence"`
	ACLVersion     int                            `json:"postgres_object_acl_version"`
	Incomplete     []string                       `json:"postgres_object_acl_incomplete_scopes"`
	Defaults       []map[string]any               `json:"postgres_default_privileges"`
	RoleAttributes map[string]json.RawMessage     `json:"-"`
}

type postgresHBAMatch struct {
	Endpoint      string `json:"endpoint"`
	ServerAddress string `json:"server_address"`
	ServerRole    string `json:"server_role"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
	RuleNumber    int    `json:"rule_number,omitempty"`
	AuthMethod    string `json:"auth_method,omitempty"`
}

type postgresHBAAssessment struct {
	SourceIP             string             `json:"database_peer_source_ip"`
	SourceIPMeaning      string             `json:"source_ip_meaning"`
	TLS                  bool               `json:"tls"`
	Evidence             string             `json:"evidence"`
	ApplicationReadiness string             `json:"application_readiness"`
	PrimaryCoverage      string             `json:"primary_coverage"`
	StandbyCoverage      string             `json:"standby_coverage"`
	Endpoints            []postgresHBAMatch `json:"endpoints"`
	Limitations          []string           `json:"limitations"`
}

type postgresAccessDiagnosticsResponse struct {
	AccountID               uuid.UUID               `json:"account_id"`
	Database                string                  `json:"database"`
	Profile                 string                  `json:"profile"`
	Assessment              string                  `json:"assessment"`
	SnapshotExcessObserved  bool                    `json:"snapshot_excess_observed"`
	Findings                []postgresAccessFinding `json:"findings"`
	FindingsTruncated       bool                    `json:"findings_truncated"`
	EvidenceTruncated       bool                    `json:"evidence_truncated"`
	FutureDefaultPrivileges []map[string]any        `json:"future_default_privileges"`
	DefaultsTruncated       bool                    `json:"defaults_truncated"`
	Limitations             []string                `json:"limitations"`
	Inventory               *inventoryFreshness     `json:"inventory"`
	HBA                     postgresHBAAssessment   `json:"hba"`
}

func postgresDiagnosticSources(identity string, evidence adapter.PostgresAccessEvidence) map[string]postgresAccessSource {
	out := map[string]postgresAccessSource{identity: {Kind: "direct", Role: identity, Activation: "current"}}
	for _, row := range evidence.Memberships {
		if row.Member != identity || row.Role == "pg_database_owner" {
			continue
		}
		if row.Usage {
			out[row.Role] = postgresAccessSource{Kind: "inherited_role", Role: row.Role, Activation: "current"}
		} else if row.SetRole {
			out[row.Role] = postgresAccessSource{Kind: "set_role", Role: row.Role, Activation: "set_role_required"}
		}
	}
	return out
}

func postgresPrivilegeWithinProfile(profile, kind, privilege string) bool {
	switch kind {
	case "database":
		return privilege == "CONNECT"
	case "schema":
		return privilege == "USAGE"
	case "sequence":
		return privilege == "SELECT" || profile == "read_write" && privilege == "UPDATE"
	case "table", "view", "materialized_view", "column":
		return privilege == "SELECT" || profile == "read_write" && slices.Contains([]string{"INSERT", "UPDATE", "DELETE"}, privilege)
	}
	return false
}

func addPostgresDiagnosticFinding(out *postgresAccessDiagnosticsResponse, finding postgresAccessFinding) {
	out.SnapshotExcessObserved = true
	if len(out.Findings) >= postgresDiagnosticFindingLimit {
		out.FindingsTruncated = true
		return
	}
	out.Findings = append(out.Findings, finding)
}

func assessPostgresPrivileges(out *postgresAccessDiagnosticsResponse, identity string, attrs json.RawMessage,
	resources []postgresDiagnosticResource, grants []postgresDiagnosticGrant, topology postgresDiagnosticTopology,
	sources map[string]postgresAccessSource,
) {
	byID := map[uuid.UUID]postgresDiagnosticResource{}
	for _, resource := range resources {
		byID[resource.ID] = resource
		properties := decodeAttributes(resource.Attributes)
		owner, _ := properties["owner"].(string)
		if resource.Kind == "database" {
			if source, ok := sources[owner]; ok {
				sources["pg_database_owner"] = postgresAccessSource{Kind: "database_owner", Role: "pg_database_owner", Activation: source.Activation}
			}
		}
	}
	for _, resource := range resources {
		properties := decodeAttributes(resource.Attributes)
		owner, _ := properties["owner"].(string)
		if source, ok := sources[owner]; ok {
			source.Kind = "ownership"
			addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: resource.Path, ObjectKind: resource.Kind, Privilege: "OWNER", Source: source})
		}
		if public, ok := properties["public_privileges"].([]any); ok {
			for _, item := range public {
				privilege, ok := item.(string)
				if !ok {
					continue
				}
				kind := resource.Kind
				if strings.Contains(privilege, " (") {
					kind = "column"
				}
				base, _, _ := strings.Cut(privilege, " (")
				if !postgresPrivilegeWithinProfile(out.Profile, kind, base) {
					addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: resource.Path, ObjectKind: kind, Privilege: privilege, Source: postgresAccessSource{Kind: "public", Activation: "current"}})
				}
			}
		}
	}
	for _, grant := range grants {
		source, ok := sources[grant.Subject]
		if !ok {
			continue
		}
		resource, ok := byID[grant.ResourceID]
		if !ok {
			out.EvidenceTruncated = true
			continue
		}
		properties := decodeAttributes(grant.Attributes)
		kind, _ := properties["object_kind"].(string)
		privilege, _ := properties["privilege"].(string)
		column, _ := properties["column"].(string)
		grantOption := false
		var binding struct {
			Grantors []struct {
				Name        string `json:"name"`
				GrantOption bool   `json:"grant_option"`
			} `json:"grantors"`
		}
		grantors := []string{}
		if json.Unmarshal(grant.BindingAttributes, &binding) == nil {
			for _, grantor := range binding.Grantors {
				grantOption = grantOption || grantor.GrantOption
				if grantor.Name != "" {
					grantors = append(grantors, grantor.Name)
				}
			}
		}
		slices.Sort(grantors)
		grantors = slices.Compact(grantors)
		grantorsTruncated := len(grantors) > 10
		if grantorsTruncated {
			grantors = grantors[:10]
		}
		if privilege == "" {
			continue
		}
		if !postgresPrivilegeWithinProfile(out.Profile, kind, privilege) || grantOption {
			path := resource.Path
			if column != "" {
				path += "." + column
			}
			addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: path, ObjectKind: kind, Privilege: privilege, Source: source, GrantOption: grantOption, Grantors: grantors, GrantorsTruncated: grantorsTruncated})
		}
	}
	properties := decodeAttributes(attrs)
	for _, attribute := range []string{"superuser", "createdb", "createrole", "replication", "bypassrls"} {
		if value, _ := properties[attribute].(bool); value {
			addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: "cluster", ObjectKind: "role_attribute", Privilege: strings.ToUpper(attribute), Source: postgresAccessSource{Kind: "role_attribute", Role: identity, Activation: "current"}})
		}
	}
	for _, reachability := range topology.Evidence.Memberships {
		if reachability.Member != identity || !reachability.SetRole {
			continue
		}
		roleProperties := decodeAttributes(topology.RoleAttributes[reachability.Role])
		for _, attribute := range []string{"superuser", "createdb", "createrole", "replication", "bypassrls"} {
			if value, _ := roleProperties[attribute].(bool); value {
				addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: "cluster", ObjectKind: "role_attribute", Privilege: strings.ToUpper(attribute), Source: postgresAccessSource{Kind: "set_role", Role: reachability.Role, Activation: "set_role_required"}})
			}
		}
	}
	roles := make([]string, 0, len(sources))
	for role := range sources {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	for _, role := range roles {
		source := sources[role]
		if role == "pg_write_all_data" || role == "pg_read_all_data" {
			// Native data roles cover every database; their scope exceeds this request's single database.
			source.Kind = "native_role"
			addPostgresDiagnosticFinding(out, postgresAccessFinding{Resource: "all_databases", ObjectKind: "native_role", Privilege: role, Source: source})
		}
	}
	for _, row := range topology.Defaults {
		if row["database"] != out.Database {
			continue
		}
		grantee, _ := row["grantee"].(string)
		if _, ok := sources[grantee]; !ok && grantee != "PUBLIC" {
			continue
		}
		if len(out.FutureDefaultPrivileges) >= postgresDiagnosticFindingLimit {
			out.DefaultsTruncated = true
			continue
		}
		// Project known fields only; old snapshots are not trusted to define response fields.
		source := postgresAccessSource{Kind: "public", Activation: "current"}
		if grantee != "PUBLIC" {
			source = sources[grantee]
		}
		future := map[string]any{"effect": "future_objects_only", "source": source}
		for _, key := range []string{"database", "creator", "schema", "kind", "grantee", "privilege", "grant_option"} {
			future[key] = row[key]
		}
		out.FutureDefaultPrivileges = append(out.FutureDefaultPrivileges, future)
	}
	if out.Inventory.Status == "current" && !out.EvidenceTruncated && topology.Evidence.MembershipsSupported && topology.ACLVersion == 1 && out.SnapshotExcessObserved {
		out.Assessment = "exceeds_profile_in_snapshot"
	}
	if !topology.Evidence.MembershipsSupported {
		out.Limitations = append(out.Limitations, "role_reachability_unavailable_or_partial")
	}
	if topology.ACLVersion != 1 {
		out.Limitations = append(out.Limitations, "object_acl_snapshot_unavailable")
	}
	if out.EvidenceTruncated {
		out.Limitations = append(out.Limitations, "bounded_evidence_truncated")
	}
}

// getPostgresAccessDiagnostics reads one repeatable metadata snapshot; it never connects as the account.
func (s *Server) getPostgresAccessDiagnostics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	database := r.URL.Query().Get("database")
	profile := r.URL.Query().Get("profile")
	sourceIP, err := netip.ParseAddr(r.URL.Query().Get("source_ip"))
	tlsRaw := r.URL.Query().Get("tls")
	if database == "" || len(database) > 63 || strings.ContainsRune(database, 0) || (profile != "read" && profile != "read_write") || err != nil || sourceIP.Zone() != "" || (tlsRaw != "true" && tlsRaw != "false") {
		respondError(w, http.StatusBadRequest, "database, profile=read|read_write, database-peer source_ip and tls=true|false are required")
		return
	}
	ctx := r.Context()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	account, err := s.inventory.GetAccount(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, account.ConnectionID)) {
		return
	}
	connection, err := s.connections.Get(ctx, tx, account.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if connection.Engine != "postgres" || account.Kind != inventory.AccountKindLogin {
		respondError(w, http.StatusBadRequest, "PostgreSQL LOGIN account required")
		return
	}
	var topology postgresDiagnosticTopology
	_ = json.Unmarshal(connection.Topology, &topology)
	policies, err := rolepolicies.NewStore().List(ctx, tx, connection.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	freshness, err := inventoryFreshnessForSnapshot(ctx, tx, connection, policies)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := postgresAccessDiagnosticsResponse{AccountID: id, Database: database, Profile: profile, Assessment: "unknown", Findings: []postgresAccessFinding{}, FutureDefaultPrivileges: []map[string]any{}, Inventory: freshness,
		Limitations: []string{"metadata_snapshot_not_live_login", "absence_of_findings_is_not_profile_compliance", "grants_do_not_prove_database_connect_schema_usage_or_row_access", "rls_functions_types_and_other_object_classes_not_assessed", "implicit_default_public_acl_not_fully_observed"}}
	if connection.LastDiscoveryAt != nil && time.Since(*connection.LastDiscoveryAt) > 15*time.Minute {
		out.Inventory.Status = "stale"
		out.Inventory.RefreshRequired = true
		out.Inventory.Reason = "snapshot_older_than_15_minutes"
	}
	if !inventory.IsLiveAccountStatus(account.Status) {
		out.Inventory.Status = "stale"
		out.Inventory.RefreshRequired = true
		out.Inventory.Reason = "account_not_observed_live"
	}
	sources := postgresDiagnosticSources(account.EngineIdentity, topology.Evidence)
	resources := []postgresDiagnosticResource{}
	rows, err := tx.Query(ctx, `with recursive scope as (
	 select id,kind,canonical_path,attributes from resources where connection_id=$1 and kind='database' and name=$2 and status='observed'
	 union all select r.id,r.kind,r.canonical_path,r.attributes from resources r join scope p on r.parent_id=p.id where r.connection_id=$1 and r.status='observed'
	) select id,kind,canonical_path,attributes from scope where kind<>'index' order by canonical_path,id limit $3`, connection.ID, database, postgresDiagnosticEvidenceLimit+1)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	for rows.Next() {
		var resource postgresDiagnosticResource
		if err := rows.Scan(&resource.ID, &resource.Kind, &resource.Path, &resource.Attributes); err != nil {
			rows.Close()
			respondStoreError(ctx, w, err)
			return
		}
		resources = append(resources, resource)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(resources) == 0 {
		respondError(w, http.StatusNotFound, "observed database not found")
		return
	}
	if len(resources) > postgresDiagnosticEvidenceLimit {
		resources = resources[:postgresDiagnosticEvidenceLimit]
		out.EvidenceTruncated = true
	}
	// pg_database_owner is virtual and must be resolved for the requested database, not the maintenance database.
	for _, resource := range resources {
		if resource.Kind == "database" {
			owner, _ := decodeAttributes(resource.Attributes)["owner"].(string)
			if source, ok := sources[owner]; ok {
				sources["pg_database_owner"] = postgresAccessSource{Kind: "database_owner", Role: "pg_database_owner", Activation: source.Activation}
			}
		}
	}
	subjects := make([]string, 0, len(sources))
	for subject := range sources {
		subjects = append(subjects, subject)
	}
	slices.Sort(subjects)
	rows, err = tx.Query(ctx, `select engine_identity,attributes from accounts where connection_id=$1 and engine_identity=any($2::text[]) and status in ('active','disabled') order by engine_identity limit $3`, connection.ID, subjects, postgresDiagnosticEvidenceLimit+1)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	topology.RoleAttributes = map[string]json.RawMessage{}
	for rows.Next() {
		var identity string
		var attrs json.RawMessage
		if err := rows.Scan(&identity, &attrs); err != nil {
			rows.Close()
			respondStoreError(ctx, w, err)
			return
		}
		topology.RoleAttributes[identity] = attrs
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(topology.RoleAttributes) > postgresDiagnosticEvidenceLimit {
		out.EvidenceTruncated = true
	}
	rows, err = tx.Query(ctx, `select a.engine_identity,p.scope_resource_id,p.attributes,b.observed_attributes
	 from bindings b join accounts a on a.id=b.account_id join permission_definitions p on p.id=b.permission_definition_id
	 where a.connection_id=$1 and p.connection_id=$1 and a.engine_identity=any($2::text[]) and b.observed_state='present'
	 and p.status='observed' and p.engine='postgres' and p.external_id like 'pgacl:v1:%' and p.attributes->>'database'=$3
	 order by p.external_id,a.engine_identity,b.id limit $4`, connection.ID, subjects, database, postgresDiagnosticEvidenceLimit+1)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	grants := []postgresDiagnosticGrant{}
	for rows.Next() {
		var grant postgresDiagnosticGrant
		if err := rows.Scan(&grant.Subject, &grant.ResourceID, &grant.Attributes, &grant.BindingAttributes); err != nil {
			rows.Close()
			respondStoreError(ctx, w, err)
			return
		}
		grants = append(grants, grant)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if len(grants) > postgresDiagnosticEvidenceLimit {
		grants = grants[:postgresDiagnosticEvidenceLimit]
		out.EvidenceTruncated = true
	}
	assessPostgresPrivileges(&out, account.EngineIdentity, account.Attributes, resources, grants, topology, sources)
	out.HBA = assessPostgresHBA(topology.Evidence, account.EngineIdentity, database, sourceIP.Unmap(), tlsRaw == "true", out.Inventory.Status == "current")
	respondJSON(w, http.StatusOK, out)
}

// matchUnknown prevents later rules from turning an unsupported earlier rule into a false allow.
type postgresHBATriState int

const (
	hbaNo postgresHBATriState = iota
	hbaYes
	hbaUnknown
)

func postgresHBAListMatch(values []string, identity, database string, users bool, evidence adapter.PostgresAccessEvidence) postgresHBATriState {
	result := hbaNo
	for _, value := range values {
		if value == "all" {
			return hbaYes
		}
		if users && value == identity && !strings.HasPrefix(value, "+") && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "@") {
			return hbaYes
		}
		if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "@") {
			result = hbaUnknown
			continue
		}
		role := ""
		if users && strings.HasPrefix(value, "+") {
			role = strings.TrimPrefix(value, "+")
		}
		if !users && (value == "samegroup" || value == "samerole") {
			role = database
		}
		if !users && value == "sameuser" {
			if identity == database {
				return hbaYes
			}
			continue
		}
		if !users && value == "replication" {
			continue
		}
		if !users && role == "" && value == database {
			return hbaYes
		}
		if role != "" {
			if role == "pg_database_owner" {
				result = hbaUnknown
				continue
			}
			if role == identity {
				return hbaYes
			}
			found := false
			for _, row := range evidence.Memberships {
				if row.Member == identity && row.Role == role && row.IsMember {
					found = true
					break
				}
			}
			if found {
				return hbaYes
			}
			if !evidence.MembershipsSupported || evidence.MembershipsTruncated {
				result = hbaUnknown
			}
		}
	}
	return result
}

func postgresHBAAddressMatch(address, mask string, source netip.Addr) postgresHBATriState {
	if address == "all" {
		return hbaYes
	}
	if prefix, err := netip.ParsePrefix(address); err == nil {
		if prefix.Contains(source) {
			return hbaYes
		}
		return hbaNo
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return hbaUnknown
	}
	ip = ip.Unmap()
	if mask == "" {
		if ip == source {
			return hbaYes
		}
		return hbaNo
	}
	maskIP := net.ParseIP(mask)
	if maskIP == nil {
		return hbaUnknown
	}
	var parsedMask net.IPMask
	if ip.Is4() {
		if maskIP.To4() == nil {
			return hbaUnknown
		}
		parsedMask = net.IPMask(maskIP.To4())
	} else {
		parsedMask = net.IPMask(maskIP.To16())
	}
	ones, bits := parsedMask.Size()
	if bits == 0 {
		return hbaUnknown
	}
	if netip.PrefixFrom(ip, ones).Contains(source) {
		return hbaYes
	}
	return hbaNo
}

func postgresHBARuleMatch(rule adapter.PostgresHBARule, identity, database string, source netip.Addr, tls bool, evidence adapter.PostgresAccessEvidence) postgresHBATriState {
	if rule.Error != "" {
		return hbaUnknown
	}
	if rule.Type == "local" || rule.Type == "hostssl" && !tls || rule.Type == "hostnossl" && tls {
		return hbaNo
	}
	db := postgresHBAListMatch(rule.Databases, identity, database, false, evidence)
	user := postgresHBAListMatch(rule.Users, identity, database, true, evidence)
	address := postgresHBAAddressMatch(rule.Address, rule.Netmask, source)
	if db == hbaNo || user == hbaNo || address == hbaNo {
		return hbaNo
	}
	if rule.Error != "" || len(rule.Options) > 0 || db == hbaUnknown || user == hbaUnknown || address == hbaUnknown || (rule.Type != "host" && rule.Type != "hostssl" && rule.Type != "hostnossl") {
		return hbaUnknown
	}
	return hbaYes
}

func assessPostgresHBA(evidence adapter.PostgresAccessEvidence, identity, database string, source netip.Addr, tls, current bool) postgresHBAAssessment {
	out := postgresHBAAssessment{SourceIP: source.String(), SourceIPMeaning: "peer_seen_by_database_after_haproxy_or_nat", TLS: tls, Evidence: "pg_hba_file_rules_file_contents", ApplicationReadiness: "not_verified", PrimaryCoverage: "unknown", StandbyCoverage: "unknown", Endpoints: []postgresHBAMatch{},
		Limitations: []string{"file_rules_may_differ_from_last_loaded_configuration", "keyword_quoting_not_preserved_by_view", "static_match_does_not_verify_network_credentials_login_or_application", "only_configured_endpoints_probed"}}
	for index, endpoint := range evidence.Endpoints {
		if index >= 8 {
			out.Limitations = append(out.Limitations, "configured_endpoints_truncated")
			break
		}
		match := postgresHBAMatch{Endpoint: endpoint.Endpoint, ServerAddress: endpoint.ServerAddress, ServerRole: endpoint.ServerRole, Status: "unknown"}
		if endpoint.ServerRole == "primary" && endpoint.Available {
			out.PrimaryCoverage = "observed"
		}
		if endpoint.ServerRole == "standby" && endpoint.Available {
			out.StandbyCoverage = "observed"
		}
		if !current {
			if out.PrimaryCoverage == "observed" {
				out.PrimaryCoverage = "stale"
			}
			if out.StandbyCoverage == "observed" {
				out.StandbyCoverage = "stale"
			}
		}
		switch {
		case !current:
			match.Reason = "stale_or_partial_inventory"
		case !endpoint.Available:
			match.Reason = "endpoint_hba_unavailable"
		default:
			rules := slices.Clone(endpoint.Rules)
			slices.SortStableFunc(rules, func(a, b adapter.PostgresHBARule) int { return cmp.Compare(a.Number, b.Number) })
			if len(rules) > 500 {
				rules = rules[:500]
				endpoint.Truncated = true
			}
			for _, rule := range rules {
				state := postgresHBARuleMatch(rule, identity, database, source, tls, evidence)
				if state == hbaNo {
					continue
				}
				match.RuleNumber = rule.Number
				if state == hbaUnknown {
					match.Reason = "earlier_rule_not_evaluable"
					break
				}
				match.Status = "file_rule_match"
				match.AuthMethod = rule.AuthMethod
				if rule.AuthMethod == "reject" {
					match.Status = "file_reject"
				}
				break
			}
			if match.RuleNumber == 0 && match.Reason == "" {
				if endpoint.Truncated {
					match.Reason = "rules_truncated"
				} else {
					match.Status = "file_no_matching_rule"
				}
			}
		}
		out.Endpoints = append(out.Endpoints, match)
	}
	if evidence.EndpointsTruncated {
		out.Limitations = append(out.Limitations, "configured_endpoints_truncated")
	}
	return out
}
