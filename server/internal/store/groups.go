package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Group, makine grubudur: statik (üye listesi) veya dinamik (kural).
type Group struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Kind        string     `json:"kind"` // static, dynamic
	Rule        *GroupRule `json:"rule"`
	CreatedAt   time.Time  `json:"created_at"`
	// Members, listede hesaplanan üye sayısıdır (kullanıcı kapsamına göre).
	Members int `json:"members"`
}

// GroupRule, dinamik grubun kuralıdır. Match "all" ise tüm koşullar, "any" ise en az biri
// sağlanmalıdır.
type GroupRule struct {
	Match      string           `json:"match"`
	Conditions []GroupCondition `json:"conditions"`
}

// GroupCondition, kuraldaki tek koşuldur. Field ve Op beyaz listeden seçilir; Value (ve
// uygulama koşulunda Name) SQL'e yalnızca parametre olarak girer.
//
//	platform       eq                 windows | darwin
//	os_name        contains | eq      "Windows 11"
//	os_build       version_lt | version_gte | prefix
//	hostname       contains | prefix | eq
//	ad_ou          under              "OU=Şubeler,DC=ornek,DC=local" (OU ve altı)
//	tag            has                "sunucu"
//	app            installed | missing | version_lt | version_gte   (Name = uygulama adı içerir)
//	missing_patch  has                "KB5046617"
//	agent_version  version_lt | version_gte
//	risk           gte                "80"
type GroupCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
	Name  string `json:"name,omitempty"`
}

var groupOps = map[string][]string{
	"platform":      {"eq"},
	"os_name":       {"contains", "eq"},
	"os_build":      {"version_lt", "version_gte", "prefix"},
	"hostname":      {"contains", "prefix", "eq"},
	"ad_ou":         {"under"},
	"tag":           {"has"},
	"app":           {"installed", "missing", "version_lt", "version_gte"},
	"missing_patch": {"has"},
	"agent_version": {"version_lt", "version_gte"},
	"risk":          {"gte"},
}

// TagPattern, etiketlerin izin verilen biçimidir (veritabanı kısıtıyla aynı).
var TagPattern = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,39}$`)

// Validate, kuralın biçimini denetler.
func (r *GroupRule) Validate() error {
	if r.Match != "all" && r.Match != "any" {
		return errors.New("eşleşme all veya any olmalı")
	}
	if len(r.Conditions) == 0 || len(r.Conditions) > 10 {
		return errors.New("1-10 koşul gerekli")
	}
	for i, c := range r.Conditions {
		ops, ok := groupOps[c.Field]
		if !ok {
			return fmt.Errorf("koşul %d: bilinmeyen alan %q", i+1, c.Field)
		}
		valid := false
		for _, op := range ops {
			valid = valid || op == c.Op
		}
		if !valid {
			return fmt.Errorf("koşul %d: %s için geçersiz işlem %q", i+1, c.Field, c.Op)
		}
		if len(c.Value) > 200 || len(c.Name) > 200 {
			return fmt.Errorf("koşul %d: değer çok uzun", i+1)
		}
		needValue := !(c.Field == "app" && (c.Op == "installed" || c.Op == "missing"))
		if needValue && strings.TrimSpace(c.Value) == "" {
			return fmt.Errorf("koşul %d: değer gerekli", i+1)
		}
		if c.Field == "app" && strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("koşul %d: uygulama adı gerekli", i+1)
		}
		if c.Field == "risk" {
			if _, err := strconv.ParseFloat(c.Value, 64); err != nil {
				return fmt.Errorf("koşul %d: risk sayı olmalı", i+1)
			}
		}
	}
	return nil
}

// sql, kuralı m (machines) takma adına göre bir WHERE parçasına çevirir.
func (r *GroupRule) sql(arg func(any) string) string {
	parts := make([]string, 0, len(r.Conditions))
	for _, c := range r.Conditions {
		parts = append(parts, "("+conditionSQL(c, arg)+")")
	}
	sep := " AND "
	if r.Match == "any" {
		sep = " OR "
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func like(v string) string { return "%" + escapeLike(strings.TrimSpace(v)) + "%" }

func conditionSQL(c GroupCondition, arg func(any) string) string {
	v := strings.TrimSpace(c.Value)
	verCmp := func(col string) string {
		op := "<"
		if c.Op == "version_gte" {
			op = ">="
		}
		return fmt.Sprintf("berops_version_key(%s) %s berops_version_key(%s)", col, op, arg(v))
	}
	switch c.Field {
	case "platform":
		return "m.os_platform = " + arg(v)
	case "os_name":
		if c.Op == "eq" {
			return "lower(m.os_name) = lower(" + arg(v) + ")"
		}
		return "m.os_name ILIKE " + arg(like(v))
	case "os_build":
		if c.Op == "prefix" {
			return "m.os_build LIKE " + arg(escapeLike(v)+"%")
		}
		return "m.os_build <> '' AND " + verCmp("m.os_build")
	case "hostname":
		switch c.Op {
		case "eq":
			return "lower(m.hostname) = lower(" + arg(v) + ")"
		case "prefix":
			return "m.hostname ILIKE " + arg(escapeLike(v)+"%")
		}
		return "m.hostname ILIKE " + arg(like(v))
	case "ad_ou":
		return scopeCond("m.ad_ou", []string{v}, arg)
	case "tag":
		return "EXISTS (SELECT 1 FROM machine_tags t WHERE t.machine_id = m.id AND lower(t.tag) = lower(" + arg(v) + "))"
	case "app":
		base := "SELECT 1 FROM installed_apps a WHERE a.machine_id = m.id AND a.name ILIKE " + arg(like(c.Name))
		switch c.Op {
		case "missing":
			return "NOT EXISTS (" + base + ")"
		case "installed":
			return "EXISTS (" + base + ")"
		}
		return "EXISTS (" + base + " AND " + verCmp("a.version") + ")"
	case "missing_patch":
		return "EXISTS (SELECT 1 FROM missing_patches p WHERE p.machine_id = m.id AND (upper(p.kb) = upper(" + arg(v) +
			") OR p.update_id = " + arg(v) + "))"
	case "agent_version":
		return verCmp("m.agent_version")
	case "risk":
		f, _ := strconv.ParseFloat(v, 64)
		return "EXISTS (SELECT 1 FROM machine_risk r WHERE r.machine_id = m.id AND r.max_risk >= " + arg(f) + ")"
	}
	return "false"
}

// GroupCond, grubun üyeliğini m takma adına göre bir WHERE parçası olarak döner.
func GroupCond(g *Group, arg func(any) string) string {
	if g.Kind == "dynamic" && g.Rule != nil {
		return g.Rule.sql(arg)
	}
	return "EXISTS (SELECT 1 FROM machine_group_members gm WHERE gm.machine_id = m.id AND gm.group_id = " + arg(g.ID) + ")"
}

const groupColumns = `id, name, description, kind, rule, created_at`

func scanGroup(row interface{ Scan(...any) error }) (*Group, error) {
	var g Group
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Kind, &g.Rule, &g.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

// GetGroup, grubu döner.
func (s *Store) GetGroup(ctx context.Context, id string) (*Group, error) {
	return scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupColumns+` FROM machine_groups WHERE id = $1`, id))
}

// ListGroups, grupları ve kullanıcının kapsamındaki aktif üye sayılarını döner.
func (s *Store) ListGroups(ctx context.Context, scope []string) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+groupColumns+` FROM machine_groups ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	groups := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		groups = append(groups, *g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range groups {
		ids, err := s.GroupMachineIDs(ctx, &groups[i], scope)
		if err != nil {
			return nil, err
		}
		groups[i].Members = len(ids)
	}
	return groups, nil
}

// GroupMachineIDs, grubun kullanıcı kapsamındaki aktif makinelerini döner.
func (s *Store) GroupMachineIDs(ctx context.Context, g *Group, scope []string) ([]string, error) {
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	cond := GroupCond(g, arg)
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		cond += " AND " + c
	}
	rows, err := s.pool.Query(ctx, `SELECT m.id FROM machines m WHERE m.status = 'active' AND `+cond+` LIMIT 10000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ActiveMachineIDs, kullanıcı kapsamındaki tüm aktif makineleri döner ("tüm filo" hedefi).
func (s *Store) ActiveMachineIDs(ctx context.Context, scope []string) ([]string, error) {
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	cond := "true"
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		cond = c
	}
	rows, err := s.pool.Query(ctx, `SELECT m.id FROM machines m WHERE m.status = 'active' AND `+cond+` LIMIT 10000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SaveGroup, grubu ekler (ID boşsa) veya günceller. Statik gruptan dinamik gruba geçişte
// üye listesi silinir.
func (s *Store) SaveGroup(ctx context.Context, g Group, createdBy string) (string, error) {
	if g.ID == "" {
		err := s.pool.QueryRow(ctx, `INSERT INTO machine_groups (name, description, kind, rule, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, g.Name, g.Description, g.Kind, g.Rule, nullableUUID(createdBy)).Scan(&g.ID)
		return g.ID, conflict(err)
	}
	return g.ID, pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE machine_groups SET name = $2, description = $3, kind = $4, rule = $5 WHERE id = $1`,
			g.ID, g.Name, g.Description, g.Kind, g.Rule)
		if err != nil {
			return conflict(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if g.Kind == "dynamic" {
			_, err = tx.Exec(ctx, `DELETE FROM machine_group_members WHERE group_id = $1`, g.ID)
		}
		return err
	})
}

// DeleteGroup, grubu siler.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM machine_groups WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// UpdateGroupMembers, statik grubun üyelerini ekler ve çıkarır.
func (s *Store) UpdateGroupMembers(ctx context.Context, groupID string, add, remove []string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if len(add) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO machine_group_members (group_id, machine_id)
				SELECT $1, id FROM machines WHERE id = ANY($2::uuid[]) ON CONFLICT DO NOTHING`, groupID, add); err != nil {
				return err
			}
		}
		if len(remove) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM machine_group_members WHERE group_id = $1 AND machine_id = ANY($2::uuid[])`,
				groupID, remove); err != nil {
				return err
			}
		}
		return nil
	})
}

// MachineTags, makinenin etiketlerini döner.
func (s *Store) MachineTags(ctx context.Context, machineID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT tag FROM machine_tags WHERE machine_id = $1 ORDER BY lower(tag)`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetMachineTags, makinenin etiketlerini verilen listeyle değiştirir.
func (s *Store) SetMachineTags(ctx context.Context, machineID string, tags []string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM machine_tags WHERE machine_id = $1`, machineID); err != nil {
			return err
		}
		if len(tags) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `INSERT INTO machine_tags (machine_id, tag) SELECT $1, unnest($2::text[])`, machineID, tags)
		return err
	})
}

// AllTags, kullanılan tüm etiketleri ve makine sayılarını döner (otomatik tamamlama için).
func (s *Store) AllTags(ctx context.Context) ([]TagCount, error) {
	rows, err := s.pool.Query(ctx, `SELECT tag, count(*) FROM machine_tags GROUP BY tag ORDER BY lower(tag)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TagCount{}
	for rows.Next() {
		var t TagCount
		if err := rows.Scan(&t.Tag, &t.Machines); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TagCount, etiket ve makine sayısıdır.
type TagCount struct {
	Tag      string `json:"tag"`
	Machines int    `json:"machines"`
}

// conflict, benzersizlik ihlalini ErrConflict'e çevirir.
func conflict(err error) error {
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}
