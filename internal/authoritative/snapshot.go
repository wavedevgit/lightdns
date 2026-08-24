package authoritative

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"lightdns/internal/records"
)

type ZoneInput struct {
	Name     string
	Revision int64
	Records  []records.Record
}

type Result struct {
	Managed   bool
	Rcode     int
	Answer    []dns.RR
	Authority []dns.RR
}

type Snapshot struct {
	zones map[string]*zone
}

type zone struct {
	apex     string
	soa      *dns.SOA
	defaultNS dns.RR
	owners   map[string][]dns.RR
	existing map[string]struct{}
}

func Empty() *Snapshot {
	return &Snapshot{zones: make(map[string]*zone)}
}

func New(input []ZoneInput) (*Snapshot, error) {
	snapshot := Empty()
	for _, item := range input {
		apex := strings.ToLower(dns.Fqdn(strings.TrimSpace(item.Name)))
		if apex == "." || item.Revision <= 0 {
			return nil, fmt.Errorf("zone %q has an invalid name or revision", item.Name)
		}
		if _, exists := snapshot.zones[apex]; exists {
			return nil, fmt.Errorf("duplicate zone %s", apex)
		}
		serial := uint32(item.Revision)
		if serial == 0 {
			serial = 1
		}
		value := &zone{
			apex: apex, owners: make(map[string][]dns.RR), existing: map[string]struct{}{apex: {}},
			soa: &dns.SOA{
				Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1." + apex, Mbox: "hostmaster." + apex, Serial: serial,
				Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
			},
		}
		for index, record := range item.Records {
			rr, err := records.Parse(record)
			if err != nil {
				return nil, fmt.Errorf("zone %s record %d: %w", apex, index+1, err)
			}
			name := strings.ToLower(dns.CanonicalName(rr.Header().Name))
			if !dns.IsSubDomain(apex, name) {
				return nil, fmt.Errorf("record %s is outside zone %s", name, apex)
			}
			if name == apex && rr.Header().Rrtype == dns.TypeCNAME {
				return nil, fmt.Errorf("zone apex %s cannot be a CNAME", apex)
			}
			if name != apex && rr.Header().Rrtype == dns.TypeNS {
				return nil, fmt.Errorf("delegation NS records are not supported: %s", name)
			}
			value.owners[name] = append(value.owners[name], rr)
			for node := name; dns.IsSubDomain(apex, node); {
				value.existing[node] = struct{}{}
				if node == apex {
					break
				}
				dot := strings.IndexByte(node, '.')
				if dot < 0 || dot == len(node)-1 {
					break
				}
				node = node[dot+1:]
			}
		}
		for name, values := range value.owners {
			hasCNAME := false
			for _, rr := range values {
				hasCNAME = hasCNAME || rr.Header().Rrtype == dns.TypeCNAME
			}
			if hasCNAME && len(values) != 1 {
				return nil, fmt.Errorf("%s: CNAME cannot coexist with other records", name)
			}
		}
		apexHasNS := false
		for _, rr := range value.owners[apex] {
			if ns, ok := rr.(*dns.NS); ok {
				apexHasNS = true
				value.soa.Ns = ns.Ns
				break
			}
		}
		if !apexHasNS {
			value.defaultNS = &dns.NS{
				Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  value.soa.Ns,
			}
		}
		snapshot.zones[apex] = value
	}
	return snapshot, nil
}

func (s *Snapshot) Lookup(question dns.Question) Result {
	name := strings.ToLower(dns.CanonicalName(question.Name))
	value := s.findZone(name)
	if value == nil {
		return Result{}
	}
	if question.Qclass != dns.ClassINET {
		return Result{Managed: true, Rcode: dns.RcodeNotImplemented}
	}
	if name == value.apex && (question.Qtype == dns.TypeSOA || question.Qtype == dns.TypeANY) {
		return value.answer(name, question.Qtype, value.owners[name])
	}
	if recordsAtName, exists := value.owners[name]; exists {
		return value.answer(name, question.Qtype, recordsAtName)
	}
	if _, exists := value.existing[name]; exists {
		return value.negative(dns.RcodeSuccess)
	}
	closest := name
	for {
		dot := strings.IndexByte(closest, '.')
		if dot < 0 || dot == len(closest)-1 {
			break
		}
		closest = closest[dot+1:]
		if _, exists := value.existing[closest]; !exists {
			continue
		}
		wildcard := "*." + closest
		if wildcardRecords, exists := value.owners[wildcard]; exists {
			return value.answer(name, question.Qtype, wildcardRecords)
		}
		break
	}
	return value.negative(dns.RcodeNameError)
}

func (s *Snapshot) findZone(name string) *zone {
	for candidate := name; ; {
		if value := s.zones[candidate]; value != nil {
			return value
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 || dot == len(candidate)-1 {
			return nil
		}
		candidate = candidate[dot+1:]
	}
}

func (z *zone) answer(name string, queryType uint16, values []dns.RR) Result {
	result := Result{Managed: true, Rcode: dns.RcodeSuccess}
	for _, rr := range values {
		if queryType != dns.TypeANY && rr.Header().Rrtype != queryType && rr.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		copy := dns.Copy(rr)
		if rr.Header().Name != name {
			copy.Header().Name = name
		}
		result.Answer = append(result.Answer, copy)
	}
	if name == z.apex && (queryType == dns.TypeSOA || queryType == dns.TypeANY) {
		result.Answer = append(result.Answer, dns.Copy(z.soa))
	}
	if name == z.apex && z.defaultNS != nil && (queryType == dns.TypeNS || queryType == dns.TypeANY) {
		result.Answer = append(result.Answer, dns.Copy(z.defaultNS))
	}
	if len(result.Answer) == 0 {
		result.Authority = []dns.RR{dns.Copy(z.soa)}
	}
	return result
}

func (z *zone) negative(rcode int) Result {
	return Result{Managed: true, Rcode: rcode, Authority: []dns.RR{dns.Copy(z.soa)}}
}
