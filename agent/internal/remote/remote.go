// Package remote, konsoldan açılan uzaktan yönetim oturumlarını yürütür: performans
// bilgisi, servis listesi ve kontrolü, Windows kayıt defteri. Her istek imzalı olmalı ve
// makinede ilgili özellik açık olmalıdır; aksi halde ajan isteği reddeder.
package remote

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// Client, uzaktan yönetim uç noktalarına erişimdir.
type Client interface {
	RemotePoll(ctx context.Context) (*protocol.SignedJob, error)
	RemoteResult(ctx context.Context, id string, r protocol.RemoteResult) error
}

// Handler, bir işlemi yürütür (testlerde değiştirilebilir).
type Handler func(ctx context.Context, op string, params json.RawMessage) (any, error)

// Session, uzaktan oturum yöneticisidir.
type Session struct {
	Client    Client
	Log       *slog.Logger
	MachineID string
	Key       func() ed25519.PublicKey
	Handle    Handler

	mu      sync.Mutex
	flags   protocol.RemoteFlags
	until   time.Time
	running bool
	now     func() time.Time
}

// New, varsayılan işleyicilerle oturum yöneticisi üretir.
func New(c Client, log *slog.Logger, machineID string, key func() ed25519.PublicKey) *Session {
	return &Session{Client: c, Log: log, MachineID: machineID, Key: key, Handle: Dispatch, now: time.Now}
}

// Apply, heartbeat yanıtındaki bayrakları ve oturum süresini uygular; oturum varsa uzun
// yoklama döngüsünü başlatır.
func (s *Session) Apply(ctx context.Context, resp *protocol.HeartbeatResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags = protocol.RemoteFlags{}
	if resp.Remote != nil {
		s.flags = *resp.Remote
	}
	if resp.RemoteUntil == nil || !s.flags.Any() || !resp.RemoteUntil.After(s.now()) {
		return
	}
	// Ajan saati sunucudan farklı olabileceği için süre, sunucu saatine göre kalan süre
	// olarak uygulanır.
	remaining := resp.RemoteUntil.Sub(resp.ServerTime)
	if resp.ServerTime.IsZero() {
		remaining = time.Until(*resp.RemoteUntil)
	}
	s.until = s.now().Add(min(remaining, 2*time.Hour))
	if !s.running {
		s.running = true
		go s.loop(ctx)
	}
}

func (s *Session) active() (bool, protocol.RemoteFlags) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.now().Before(s.until) {
		s.running = false
		return false, s.flags
	}
	return true, s.flags
}

func (s *Session) loop(ctx context.Context) {
	s.Log.Info("uzaktan yönetim oturumu başladı")
	failures := 0
	for {
		ok, _ := s.active()
		if !ok || ctx.Err() != nil {
			s.Log.Info("uzaktan yönetim oturumu bitti")
			return
		}
		sj, err := s.Client.RemotePoll(ctx)
		if err != nil {
			failures++
			if failures > 5 {
				s.mu.Lock()
				s.until, s.running = time.Time{}, false
				s.mu.Unlock()
				s.Log.Warn("uzaktan yönetim yoklaması durdu", "hata", err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(failures) * 2 * time.Second):
			}
			continue
		}
		failures = 0
		if sj == nil {
			continue // istek yok (uzun yoklama zaman aşımı)
		}
		go s.serve(ctx, *sj)
	}
}

func (s *Session) serve(ctx context.Context, sj protocol.SignedJob) {
	req, err := sj.VerifyRemote(s.Key(), s.MachineID, s.now())
	if err != nil {
		// İmzası doğrulanamayan isteğin kimliğine güvenilemez; yanıt verilmez.
		s.Log.Error("uzaktan istek reddedildi", "hata", err)
		return
	}
	_, flags := s.active()
	res := protocol.RemoteResult{OK: true}
	if !flags.Allows(req.Op) {
		res = protocol.RemoteResult{Error: "bu özellik makinede kapalı"}
	} else {
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		data, err := s.Handle(cctx, req.Op, req.Params)
		cancel()
		if err != nil {
			res = protocol.RemoteResult{Error: err.Error()}
		} else if res.Data, err = json.Marshal(data); err != nil {
			res = protocol.RemoteResult{Error: err.Error()}
		}
	}
	if err := s.Client.RemoteResult(context.WithoutCancel(ctx), req.ID, res); err != nil {
		s.Log.Warn("uzaktan sonuç gönderilemedi", "istek", req.ID, "hata", err)
	}
}

// ErrUnsupported, işlem bu platformda desteklenmiyorsa döner.
var ErrUnsupported = errors.New("bu işlem bu platformda desteklenmiyor")

// Dispatch, işlemi platform uygulamasına yönlendirir.
func Dispatch(ctx context.Context, op string, params json.RawMessage) (any, error) {
	switch op {
	case protocol.RemotePerformance:
		return Performance(ctx)
	case protocol.RemoteServicesList:
		return ListServices(ctx)
	case protocol.RemoteServicesControl:
		var p protocol.ServiceControlParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if p.Action != "start" && p.Action != "stop" && p.Action != "restart" {
			return nil, fmt.Errorf("geçersiz servis işlemi: %s", p.Action)
		}
		return nil, ControlService(ctx, p.Name, p.Action)
	case protocol.RemoteRegistryList:
		var p protocol.RegistryPathParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return RegistryList(p.Path)
	case protocol.RemoteRegistrySet:
		var p protocol.RegistrySetParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return RegistrySet(p.Path, p.Value)
	case protocol.RemoteRegistryDelete:
		var p protocol.RegistryDeleteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return RegistryDelete(p.Path, p.Name)
	}
	return nil, fmt.Errorf("bilinmeyen işlem: %s", op)
}
