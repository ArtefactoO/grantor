package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

func (a *Adapter) discoverAccessEvidence(ctx context.Context, cfg adapter.Connection, conn *pgx.Conn, target string) adapter.PostgresAccessEvidence {
	out := adapter.PostgresAccessEvidence{Version: 1, Memberships: []adapter.PostgresRoleReachability{}, Endpoints: []adapter.PostgresHBAEndpoint{}}
	var major int
	if err := conn.QueryRow(ctx, `select current_setting('server_version_num')::integer`).Scan(&major); err == nil {
		mode := "MEMBER"
		if major >= 160000 {
			mode = "SET"
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		// A canceled best-effort query must not close the main discovery connection.
		membershipConn, connectErr := a.connect(bounded, cfg, maintenanceDatabase(cfg))
		if connectErr == nil {
			actual, known := discoverSystemIdentifier(bounded, membershipConn)
			if known && actual == target {
				rows, err := membershipConn.Query(bounded, `with recursive memberships(member,roleid) as (
		select member,roleid from pg_auth_members
		union select chain.member,edge.roleid from memberships chain join pg_auth_members edge on edge.member=chain.roleid
		)
		select m.rolname,r.rolname,true,pg_has_role(m.oid,r.oid,'USAGE'),pg_has_role(m.oid,r.oid,$1)
		from memberships membership join pg_roles m on m.oid=membership.member join pg_roles r on r.oid=membership.roleid
		where m.oid<>r.oid and m.rolname not like 'pg\_%' and r.rolname<>'pg_database_owner'
		order by m.rolname,r.rolname limit 20001`, mode)
				if err == nil {
					out.MembershipsSupported = true
					for rows.Next() {
						var row adapter.PostgresRoleReachability
						if err := rows.Scan(&row.Member, &row.Role, &row.IsMember, &row.Usage, &row.SetRole); err != nil {
							out.MembershipsSupported = false
							break
						}
						if len(out.Memberships) >= 20000 {
							out.MembershipsTruncated = true
							out.MembershipsSupported = false
							break
						}
						out.Memberships = append(out.Memberships, row)
					}
					if rows.Err() != nil {
						out.MembershipsSupported = false
					}
					rows.Close()
				}
			}
			closeQuietly(bounded, membershipConn)
		}
		cancel()
	}
	for index, endpoint := range cfg.Endpoints {
		if index >= 8 {
			out.EndpointsTruncated = true
			break
		}
		e := adapter.PostgresHBAEndpoint{Endpoint: endpoint, Rules: []adapter.PostgresHBARule{}}
		probe := cfg
		probe.Endpoints = []string{endpoint}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := a.connect(bounded, probe, maintenanceDatabase(cfg))
		if err != nil {
			cancel()
			e.ErrorCode = "endpoint_unavailable"
			out.Endpoints = append(out.Endpoints, e)
			continue
		}
		actual, known := discoverSystemIdentifier(bounded, c)
		var recovery bool
		if !known || actual != target {
			e.ErrorCode = "target_identity_unavailable_or_changed"
		} else if err = c.QueryRow(bounded, `select coalesce(inet_server_addr()::text,''),pg_is_in_recovery()`).Scan(&e.ServerAddress, &recovery); err != nil {
			e.ErrorCode = "server_identity_unavailable"
		} else if rules, truncated, ok := discoverHBARules(bounded, c); ok {
			raw, _ := json.Marshal(rules)
			if json.Unmarshal(raw, &e.Rules) == nil {
				e.Available = true
				e.Truncated = truncated
				e.ServerRole = "primary"
				if recovery {
					e.ServerRole = "standby"
				}
			} else {
				e.ErrorCode = "hba_unavailable"
			}
		} else {
			e.ErrorCode = "hba_unavailable"
		}
		closeQuietly(bounded, c)
		cancel()
		out.Endpoints = append(out.Endpoints, e)
	}
	return out
}
