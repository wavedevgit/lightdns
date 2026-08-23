package cache

import (
	"encoding/binary"
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const shardCount = 256

type entry struct {
	message *dns.Msg
	stored  time.Time
	expires time.Time
}

type shard struct {
	sync.RWMutex
	items map[string]entry
	limit int
}

type Cache struct {
	shards [shardCount]shard
	count  uint32
	minTTL time.Duration
	maxTTL time.Duration
}

func New(capacity int, minTTL, maxTTL time.Duration) *Cache {
	active := capacity
	if active < 1 {
		active = 1
	}
	if active > shardCount {
		active = shardCount
	}
	c := &Cache{minTTL: minTTL, maxTTL: maxTTL, count: uint32(active)}
	for i := range active {
		limit := 0
		if capacity > 0 {
			limit = capacity / active
			if i < capacity%active {
				limit++
			}
		}
		c.shards[i] = shard{items: make(map[string]entry), limit: limit}
	}
	return c
}

func Key(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	buf := make([]byte, len(q.Name)+5)
	copy(buf, q.Name)
	binary.BigEndian.PutUint16(buf[len(q.Name):], q.Qtype)
	binary.BigEndian.PutUint16(buf[len(q.Name)+2:], q.Qclass)
	if opt := msg.IsEdns0(); opt != nil && opt.Do() {
		buf[len(buf)-1] = 1
	}
	if msg.CheckingDisabled {
		buf[len(buf)-1] |= 2
	}
	if msg.RecursionDesired {
		buf[len(buf)-1] |= 4
	}
	return string(buf)
}

func (c *Cache) Get(key string, now time.Time) (*dns.Msg, bool) {
	s := c.forKey(key)
	s.RLock()
	item, ok := s.items[key]
	s.RUnlock()
	if !ok || !now.Before(item.expires) {
		if ok {
			s.Lock()
			delete(s.items, key)
			s.Unlock()
		}
		return nil, false
	}
	msg := item.message.Copy()
	elapsed := uint32(now.Sub(item.stored) / time.Second)
	for _, rr := range allRecords(msg) {
		if rr.Header().Ttl > elapsed {
			rr.Header().Ttl -= elapsed
		} else {
			rr.Header().Ttl = 0
		}
	}
	return msg, true
}

func (c *Cache) Set(key string, msg *dns.Msg, now time.Time) {
	if key == "" || c.shards[0].limit == 0 || !cacheable(msg) {
		return
	}
	ttl := messageTTL(msg)
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl <= 0 {
		return
	}
	s := c.forKey(key)
	s.Lock()
	if _, replacing := s.items[key]; !replacing && len(s.items) >= s.limit {
		for candidate, item := range s.items {
			if !now.Before(item.expires) || len(s.items) >= s.limit {
				delete(s.items, candidate)
			}
			if len(s.items) < s.limit {
				break
			}
		}
	}
	s.items[key] = entry{message: msg.Copy(), stored: now, expires: now.Add(ttl)}
	s.Unlock()
}

func (c *Cache) forKey(key string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &c.shards[h.Sum32()%c.count]
}

func cacheable(msg *dns.Msg) bool {
	return msg.Response && (msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError) && !msg.Truncated
}

func messageTTL(msg *dns.Msg) time.Duration {
	var minimum uint32
	for _, rr := range allRecords(msg) {
		ttl := rr.Header().Ttl
		if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		if minimum == 0 || ttl < minimum {
			minimum = ttl
		}
	}
	return time.Duration(minimum) * time.Second
}

func allRecords(msg *dns.Msg) []dns.RR {
	records := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range section {
			// OPT uses the TTL field for EDNS metadata and flags, not record expiry.
			if record.Header().Rrtype != dns.TypeOPT {
				records = append(records, record)
			}
		}
	}
	return records
}
