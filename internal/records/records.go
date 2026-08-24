package records

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Name  string `yaml:"name" json:"name"`
	Type  string `yaml:"type" json:"type"`
	Value string `yaml:"value" json:"value"`
	TTL   uint32 `yaml:"ttl" json:"ttl"`
}

type Store struct {
	records map[string][]dns.RR
}

func New(input []Record) (*Store, error) {
	store := &Store{records: make(map[string][]dns.RR)}
	for index, record := range input {
		rr, err := Parse(record)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", index+1, err)
		}
		store.records[rr.Header().Name] = append(store.records[rr.Header().Name], rr)
	}
	for name, values := range store.records {
		hasCNAME := false
		for _, value := range values {
			hasCNAME = hasCNAME || value.Header().Rrtype == dns.TypeCNAME
		}
		if hasCNAME && len(values) > 1 {
			return nil, fmt.Errorf("%s: CNAME cannot coexist with other records", name)
		}
	}
	return store, nil
}

func Parse(record Record) (dns.RR, error) {
	record.Name = strings.ToLower(dns.Fqdn(strings.TrimSpace(record.Name)))
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	if record.Name == "." || record.TTL == 0 {
		return nil, fmt.Errorf("name and a positive TTL are required")
	}
	if !supported(record.Type) {
		return nil, fmt.Errorf("unsupported type %q", record.Type)
	}
	value := strings.TrimSpace(record.Value)
	if record.Type == "TXT" {
		value = strconv.Quote(value)
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", record.Name, record.TTL, record.Type, value))
	if err != nil {
		return nil, err
	}
	return rr, nil
}

func (s *Store) Lookup(question dns.Question) (answers []dns.RR, known bool) {
	name := strings.ToLower(dns.Fqdn(question.Name))
	records, known := s.records[name]
	wildcard := false
	if !known {
		for candidate := name; ; {
			index := strings.IndexByte(candidate, '.')
			if index < 0 || index == len(candidate)-1 {
				break
			}
			candidate = candidate[index+1:]
			records, known = s.records["*."+candidate]
			if known {
				wildcard = true
				break
			}
		}
	}
	if !known {
		return nil, false
	}
	for _, rr := range records {
		if question.Qtype != dns.TypeANY && rr.Header().Rrtype != question.Qtype && rr.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		copy := dns.Copy(rr)
		if wildcard {
			copy.Header().Name = question.Name
		}
		answers = append(answers, copy)
	}
	return answers, true
}

func supported(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA":
		return true
	default:
		return false
	}
}
