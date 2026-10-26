package adapter

type PostgresRoleReachability struct {
	Member   string `json:"member"`
	Role     string `json:"role"`
	IsMember bool   `json:"is_member"`
	Usage    bool   `json:"usage"`
	SetRole  bool   `json:"set_role"`
}

type PostgresHBARule struct {
	Number     int      `json:"number"`
	Type       string   `json:"type"`
	Databases  []string `json:"databases"`
	Users      []string `json:"users"`
	Address    string   `json:"address"`
	Netmask    string   `json:"netmask"`
	AuthMethod string   `json:"auth_method"`
	Options    []string `json:"options"`
	Error      string   `json:"error"`
}

type PostgresHBAEndpoint struct {
	Endpoint      string            `json:"endpoint"`
	ServerAddress string            `json:"server_address"`
	ServerRole    string            `json:"server_role"`
	Available     bool              `json:"available"`
	Truncated     bool              `json:"truncated"`
	Rules         []PostgresHBARule `json:"rules"`
	ErrorCode     string            `json:"error_code,omitempty"`
}

type PostgresAccessEvidence struct {
	Version              int                        `json:"version"`
	MembershipsSupported bool                       `json:"memberships_supported"`
	MembershipsTruncated bool                       `json:"memberships_truncated"`
	Memberships          []PostgresRoleReachability `json:"memberships"`
	Endpoints            []PostgresHBAEndpoint      `json:"endpoints"`
	EndpointsTruncated   bool                       `json:"endpoints_truncated"`
}
