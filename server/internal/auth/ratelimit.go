package auth

import (
	"sync"
	"time"
)

// AttemptLimiter, belirli bir anahtar (IP, kullanıcı adı) için zaman penceresi içindeki
// başarısız denemeleri sayar. Bellek içi çalışır; sunucu yeniden başlatıldığında sıfırlanır.
type AttemptLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
	now      func() time.Time
}

// NewAttemptLimiter, window süresinde en fazla max başarısız denemeye izin veren sınırlayıcı üretir.
func NewAttemptLimiter(max int, window time.Duration) *AttemptLimiter {
	return &AttemptLimiter{max: max, window: window, failures: map[string][]time.Time{}, now: time.Now}
}

// WithClock, sınırlayıcının zaman kaynağını değiştirir (testler ve sunucunun ortak saati için).
func (l *AttemptLimiter) WithClock(now func() time.Time) *AttemptLimiter {
	l.now = now
	return l
}

// Allowed, anahtar için yeni denemeye izin verilip verilmediğini ve verilmiyorsa
// ne kadar beklenmesi gerektiğini döner.
func (l *AttemptLimiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.prune(key)
	if len(recent) < l.max {
		return true, 0
	}
	return false, recent[0].Add(l.window).Sub(l.now())
}

// Fail, başarısız bir denemeyi kaydeder.
func (l *AttemptLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[key] = append(l.prune(key), l.now())
}

// Reset, başarılı girişten sonra anahtarın geçmişini temizler.
func (l *AttemptLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// Sweep, süresi dolmuş kayıtları temizler; bellek büyümesini önlemek için periyodik çağrılır.
func (l *AttemptLimiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.failures {
		l.prune(k)
	}
}

// prune, pencere dışındaki denemeleri atar. Çağıran kilidi tutmalıdır.
func (l *AttemptLimiter) prune(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	list := l.failures[key]
	i := 0
	for i < len(list) && !list[i].After(cutoff) {
		i++
	}
	list = list[i:]
	if len(list) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = list
	return list
}
