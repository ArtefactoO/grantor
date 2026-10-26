package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
)

// Пороги состояния connector'а.
//
// Gateway снимает сессию после LivenessWindow молчания (по умолчанию
// минута), поэтому «давно не видели» начинается заметно позже: короткий
// разрыв во время перевыката control plane — не повод пугать оператора.
const (
	connectorOnlineWindow = 2 * time.Minute
	connectorStaleWindow  = 30 * time.Minute
)

// Состояния connector'а в ответе.
const (
	connectorStatusOnline  = "online"
	connectorStatusStale   = "stale"
	connectorStatusOffline = "offline"
)

// Источник действующего типа развёртывания.
const (
	connectorDeploymentAgent    = "agent"
	connectorDeploymentOperator = "operator"
)

// Audit-действия управления профилем connector'а.
const (
	auditActionConnectorProfileUpdated = "connector.profile_updated"
	auditActionConnectorForgotten      = "connector.forgotten"
)

// connectorJSON — один execution connector в ответе GET /api/v1/connectors.
//
// Отдаётся наблюдаемое состояние, а не желаемое: control plane знает о
// connector'е только то, что видел gateway. Секретов здесь нет —
// идентификатор берётся из CN сертификата.
type connectorJSON struct {
	ConnectorID         string `json:"connector_id"`
	Status              string `json:"status"`
	ConnectedAt         string `json:"connected_at"`
	LastSeenAt          string `json:"last_seen_at"`
	CertificateNotAfter string `json:"certificate_not_after"`
	// CertificateDaysLeft отрицателен у истёкшего сертификата: он
	// продолжает существовать, и разница между «истёк вчера» и «истёк
	// год назад» важна при разборе.
	CertificateDaysLeft int      `json:"certificate_days_left"`
	Capabilities        []string `json:"capabilities"`
	ProtocolVersion     string   `json:"protocol_version"`
	// DisplayName — имя, заданное оператором; пусто — показывается сам
	// connector_id (он же CN сертификата и потому неизменяем).
	DisplayName string `json:"display_name"`
	// DeploymentKind — действующий тип развёртывания, DeploymentSource — кто
	// его определил: "operator" (задан вручную) или "agent" (объявил сам
	// connector). Пустой kind означает, что тип неизвестен.
	DeploymentKind   string `json:"deployment_kind"`
	DeploymentSource string `json:"deployment_source"`
}

type connectorsResponse struct {
	Connectors []connectorJSON `json:"connectors"`
}

// listConnectors возвращает известные execution connector'ы.
func (s *Server) listConnectors(w http.ResponseWriter, r *http.Request) {
	if !rejectUnknownQuery(w, r) {
		return
	}
	if s.connectors == nil {
		// Control plane без gateway: connector'ов нет, и это не ошибка.
		respondJSON(w, http.StatusOK, connectorsResponse{Connectors: []connectorJSON{}})
		return
	}
	sessions, err := s.connectors.List(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list connectors")
		return
	}
	profiles, err := s.connectors.Profiles(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list connectors")
		return
	}
	now := time.Now()
	out := make([]connectorJSON, 0, len(sessions))
	for _, item := range sessions {
		out = append(out, connectorView(item, profiles[item.ConnectorID], now))
	}
	respondJSON(w, http.StatusOK, connectorsResponse{Connectors: out})
}

// connectorView переводит наблюдение в представление. Чистая функция для
// юнит-тестов.
func connectorView(item connectorstate.Session, profile connectorstate.Profile, now time.Time) connectorJSON {
	deployment, source := item.Deployment, ""
	if deployment != "" {
		source = connectorDeploymentAgent
	}
	// Оператор знает точнее агента: он видит, куда сегмент реально
	// установлен, а самообъявление — эвристика по окружению процесса.
	if profile.DeploymentKind != "" {
		deployment, source = profile.DeploymentKind, connectorDeploymentOperator
	}
	return connectorJSON{
		ConnectorID:         item.ConnectorID,
		Status:              connectorStatus(item.LastSeenAt, now),
		ConnectedAt:         item.ConnectedAt.UTC().Format(time.RFC3339),
		LastSeenAt:          item.LastSeenAt.UTC().Format(time.RFC3339),
		CertificateNotAfter: item.CertificateNotAfter.UTC().Format(time.RFC3339),
		CertificateDaysLeft: int(item.CertificateNotAfter.Sub(now).Hours() / 24),
		Capabilities:        item.Capabilities,
		ProtocolVersion:     item.ProtocolVersion,
		DisplayName:         profile.DisplayName,
		DeploymentKind:      deployment,
		DeploymentSource:    source,
	}
}

// connectorStatus классифицирует связь по времени последнего кадра.
func connectorStatus(lastSeen, now time.Time) string {
	switch age := now.Sub(lastSeen); {
	case age <= connectorOnlineWindow:
		return connectorStatusOnline
	case age <= connectorStaleWindow:
		return connectorStatusStale
	default:
		return connectorStatusOffline
	}
}

// Предел длины отображаемого имени: подпись карточки, а не описание.
const connectorDisplayNameMaxRunes = 80

// updateConnectorProfileRequest — тело PATCH /api/v1/connectors/{id}.
type updateConnectorProfileRequest struct {
	DisplayName    *string `json:"display_name"`
	DeploymentKind *string `json:"deployment_kind"`
}

// updateConnectorProfile — PATCH /api/v1/connectors/{id} (admin): имя и тип
// развёртывания.
//
// Меняется только представление: идентификатор connector'а — CN его
// клиентского сертификата, он же адресует PKI, пути Vault и релиз агента,
// поэтому переименованием здесь и не является. Профиль допускается и для
// ещё не подключавшегося connector'а: имя можно задать заранее.
func (s *Server) updateConnectorProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectorID := r.PathValue("id")
	if strings.TrimSpace(connectorID) == "" {
		respondError(w, http.StatusBadRequest, "connector id is required")
		return
	}
	if s.connectors == nil {
		respondError(w, http.StatusServiceUnavailable, "connector gateway is not configured")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	var req updateConnectorProfileRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	profiles, err := s.connectors.Profiles(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	current := profiles[connectorID]
	next := connectorstate.Profile{
		ConnectorID:    connectorID,
		DisplayName:    current.DisplayName,
		DeploymentKind: current.DeploymentKind,
		UpdatedBy:      sess.ActorID(),
	}
	if req.DisplayName != nil {
		name := strings.TrimSpace(*req.DisplayName)
		if utf8.RuneCountInString(name) > connectorDisplayNameMaxRunes {
			respondError(w, http.StatusBadRequest, fmt.Sprintf(
				"display_name must be at most %d characters", connectorDisplayNameMaxRunes))
			return
		}
		next.DisplayName = name
	}
	if req.DeploymentKind != nil {
		kind := strings.TrimSpace(*req.DeploymentKind)
		if !connectorstate.ValidDeploymentKind(kind) {
			respondError(w, http.StatusBadRequest, fmt.Sprintf(
				"deployment_kind %q is not supported (expected %q, %q, %q or empty)",
				kind, connectorstate.DeploymentKubernetes, connectorstate.DeploymentVM,
				connectorstate.DeploymentOther))
			return
		}
		next.DeploymentKind = kind
	}

	saved, err := s.connectors.SaveProfile(ctx, next)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, s.pool, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionConnectorProfileUpdated,
		Result:    audit.ResultSuccess,
	}, map[string]any{
		"connector_id":    connectorID,
		"display_name":    saved.DisplayName,
		"deployment_kind": saved.DeploymentKind,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"connector_id":    saved.ConnectorID,
		"display_name":    saved.DisplayName,
		"deployment_kind": saved.DeploymentKind,
	})
}

// forgetConnector — DELETE /api/v1/connectors/{id} (admin): убирает запись о
// connector'е.
//
// Разрешено только для offline: пока агент на связи, запись тут же появится
// снова, а оператор решит, что удаление не сработало. Данных это не рушит —
// строка описывает наблюдение, и подключившийся connector создаст её заново.
func (s *Server) forgetConnector(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectorID := r.PathValue("id")
	if strings.TrimSpace(connectorID) == "" {
		respondError(w, http.StatusBadRequest, "connector id is required")
		return
	}
	if s.connectors == nil {
		respondError(w, http.StatusServiceUnavailable, "connector gateway is not configured")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	sessions, err := s.connectors.List(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	now := time.Now()
	for _, item := range sessions {
		if item.ConnectorID != connectorID {
			continue
		}
		if connectorStatus(item.LastSeenAt, now) != connectorStatusOffline {
			respondError(w, http.StatusConflict,
				"connector is still connected: it can only be forgotten once it goes offline")
			return
		}
	}
	if _, err := s.connectors.Forget(ctx, connectorID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, s.pool, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionConnectorForgotten,
		Result:    audit.ResultSuccess,
	}, map[string]any{"connector_id": connectorID}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
