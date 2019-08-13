package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/urfave/cli"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
)

// https://github.com/miekg/dns/blob/9cfcfb2209aecb663673bd44b11f71c215186b80/types.go#L160
const _QR = 1 << 15

// https://github.com/miekg/dns/blob/d89f1e3d4bfcb2de7c3988c619d27bb6f5fac706/acceptfunc.go#L28
func msgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&_QR != 0; isResponse {
		return dns.MsgIgnore
	}

	// Allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	// For dynamic update, do no further checks
	if opcode == dns.OpcodeUpdate {
		return dns.MsgAccept
	}
	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 {
		return dns.MsgReject
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if dh.Nscount > 1 {
		return dns.MsgReject
	}
	if dh.Arcount > 2 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

type adaptor struct {
	etcdClient   *clientv3.Client
	etcdLeaseTTL int
	etcdLeases   map[string]clientv3.LeaseID
	dnsServer    *dns.Server
	errorCh      <-chan error
	addrMapping  adaptorAddrMapping
	updateMutex  sync.Mutex
}

type adaptorConfig struct {
	dnsListenAddr  string
	dnsListenProto string
	etcdDialAddr   string
	etcdLeaseTTL   string
	addrMapping    string
}

type adaptorAddrMapping map[string]string

func newAdaptor(cfg adaptorConfig) (*adaptor, error) {
	var addrMapping adaptorAddrMapping
	err := json.Unmarshal([]byte(cfg.addrMapping), &addrMapping)
	if err != nil {
		return nil, err
	}

	etcdLeaseTTL, err := strconv.Atoi(cfg.etcdLeaseTTL)
	if err != nil {
		return nil, err
	}

	dnsServer := &dns.Server{
		Addr:          cfg.dnsListenAddr,
		Net:           cfg.dnsListenProto,
		MsgAcceptFunc: msgAcceptFunc,
	}

	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{cfg.etcdDialAddr},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to etcd %s", etcdClient.ActiveConnection().Target())

	errorCh := make(chan error, 1)

	a := &adaptor{
		etcdClient:   etcdClient,
		etcdLeaseTTL: etcdLeaseTTL,
		etcdLeases:   map[string]clientv3.LeaseID{},
		dnsServer:    dnsServer,
		errorCh:      errorCh,
		addrMapping:  addrMapping,
	}

	dns.HandleFunc(".", a.handleRequest)

	go func() {
		log.Printf("Serving DNS on %s (%s) ...", dnsServer.Addr, dnsServer.Net)
		err := dnsServer.ListenAndServe()
		if err != nil {
			errorCh <- err
		}
		close(errorCh)
	}()

	return a, nil
}

func (a *adaptor) shutdown() {
	a.dnsServer.Shutdown()
	a.etcdClient.Close()
}

func domainNameToPath(prefix []string, domainName string) string {
	nameParts := dns.SplitDomainName(domainName)

	// reverse nameParts
	for i, j := 0, len(nameParts)-1; i < j; i, j = i+1, j-1 {
		nameParts[i], nameParts[j] = nameParts[j], nameParts[i]
	}

	return "/" + strings.Join(append(prefix, nameParts...), "/")
}

func (a *adaptor) recordAToJSONAndPathSuffix(record *dns.A) ([]byte, string, error) {
	type etcdValue struct {
		Host string `json:"host"`
		TTL  uint32 `json:"ttl,omitempty"`
	}

	// try to map address
	mappedAddress, ok := a.addrMapping[record.A.String()]
	if !ok {
		mappedAddress = record.A.String()
	}

	data, err := json.Marshal(etcdValue{mappedAddress, record.Hdr.Ttl})
	if err != nil {
		return nil, "", err
	}

	hasher := sha1.New()
	hasher.Write(data)

	return data, hex.EncodeToString(hasher.Sum(nil)), nil
}

func (a *adaptor) recordTXTToJSONAndPathSuffix(record *dns.TXT) ([]byte, string, error) {
	type etcdValue struct {
		Text string `json:"text"`
		TTL  uint32 `json:"ttl,omitempty"`
	}

	// only use the first TXT rrdata
	data, err := json.Marshal(etcdValue{record.Txt[0], record.Hdr.Ttl})
	if err != nil {
		return nil, "", err
	}

	hasher := sha1.New()
	hasher.Write(data)

	return data, hex.EncodeToString(hasher.Sum(nil)), nil
}

func (a *adaptor) updateEtcdLease(path string) (clientv3.LeaseID, error) {
	leaseID, ok := a.etcdLeases[path]

	if ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := a.etcdClient.KeepAliveOnce(ctx, leaseID)
		cancel()
		if err != nil {
			if err.Error() == rpctypes.ErrLeaseNotFound.Error() {
				ok = false // treat this error as not found error -> grant new lease
			} else {
				return 0, err
			}
		} else {
			log.Printf("  Refreshed lease %d", leaseID)
		}
	}

	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := a.etcdClient.Grant(ctx, int64(a.etcdLeaseTTL))
		cancel()
		if err != nil {
			return 0, err
		}

		log.Printf("  Granted new lease %d with TTL=%ds", resp.ID, a.etcdLeaseTTL)

		// store lease ID
		a.etcdLeases[path] = resp.ID
		leaseID = resp.ID
	}

	return leaseID, nil
}

func (a *adaptor) removeEtcdLeases(path string) []error {
	errs := []error{}

	for leasePath, leaseID := range a.etcdLeases {
		if strings.HasPrefix(leasePath, path) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := a.etcdClient.Revoke(ctx, leaseID)
			cancel()
			if err != nil && err.Error() != rpctypes.ErrLeaseNotFound.Error() {
				errs = append(errs, err)
			}
			log.Printf("  Revoked lease %d", leaseID)
			delete(a.etcdLeases, leasePath)
		}
	}

	return errs
}

func (a *adaptor) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	a.updateMutex.Lock()
	defer a.updateMutex.Unlock()

	log.Printf("Opcode: %d", r.Opcode)
	log.Printf("Header: %+v", r.MsgHdr)
	log.Printf("Question: %+v", r.Question[0])
	fmt.Printf("---\n%+v\n---\n", r)
	if r.Opcode == dns.OpcodeUpdate {
		log.Printf("Update for zone %s", r.Question[0].Name)
		if len(r.Answer) > 0 {
			log.Printf("Ignoring prerequisites (got %d)", len(r.Answer))
		}
		for _, record := range r.Ns {
			// 3.4.2.6 - Table Of Metavalues Used In Update Section
			//  CLASS    TYPE     RDATA    Meaning                     Function
			//  ---------------------------------------------------------------
			//  ANY      ANY      empty    Delete all RRsets from name dns.RemoveName
			//  ANY      rrset    empty    Delete an RRset             dns.RemoveRRset
			//  NONE     rrset    rr       Delete an RR from RRset     dns.Remove
			//  zone     rrset    rr       Add to an RRset             dns.Insert

			rrClass := record.Header().Class
			rrType := record.Header().Rrtype

			log.Print(record)

			if rrClass == dns.ClassANY {
				if rrType == dns.TypeANY {
					// delete all RRsets from name
					log.Printf("  Delete all RRsets from name ...")
					// Del /skydns/nipe-systems (/foo/x1)
					switch t := record.(type) {
					case *dns.ANY:
						path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
						log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						resp, err := a.etcdClient.Delete(ctx, path, clientv3.WithPrefix())
						cancel()
						if err != nil {
							log.Print(err)
						}
						log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)

						errs := a.removeEtcdLeases(path)
						for _, err := range errs {
							log.Print(err)
						}
					default:
						log.Printf("  Type %T not implemented", t)
					}
				} else {
					// delete an RRset
					log.Printf("  Delete an RRset ...")
					// Del /skydns/nipe-systems/foo
					switch t := record.(type) {
					case *dns.A:
						path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
						log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						resp, err := a.etcdClient.Delete(ctx, path, clientv3.WithPrefix())
						cancel()
						if err != nil {
							log.Print(err)
						}
						log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)

						errs := a.removeEtcdLeases(path)
						for _, err := range errs {
							log.Print(err)
						}
					case *dns.TXT:
						path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
						log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						resp, err := a.etcdClient.Delete(ctx, path, clientv3.WithPrefix())
						cancel()
						if err != nil {
							log.Print(err)
						}
						log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)

						errs := a.removeEtcdLeases(path)
						for _, err := range errs {
							log.Print(err)
						}
					default:
						log.Printf("  Type %T not implemented", t)
					}
				}
			} else if rrClass == dns.ClassNONE {
				// delete RR from RRset
				log.Printf("  Delete RR from RRset")
				// Del /skydns/nipe-systems/foo/x1
				switch t := record.(type) {
				case *dns.A:
					path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					_, sha, err := a.recordAToJSONAndPathSuffix(t)
					if err != nil {
						fmt.Println("error:", err)
					}
					path = path + "/" + sha

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Delete(ctx, path)
					cancel()
					if err != nil {
						log.Print(err)
					}
					log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)

					errs := a.removeEtcdLeases(path)
					for _, err := range errs {
						log.Print(err)
					}
				case *dns.TXT:
					path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					_, sha, err := a.recordTXTToJSONAndPathSuffix(t)
					if err != nil {
						fmt.Println("error:", err)
					}
					path = path + "/" + sha

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Delete(ctx, path)
					cancel()
					if err != nil {
						log.Print(err)
					}
					log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)

					errs := a.removeEtcdLeases(path)
					for _, err := range errs {
						log.Print(err)
					}
				default:
					log.Printf("  Type %T not implemented", t)
				}
			} else {
				// add to an RRset
				log.Printf("  Add to an RRset")
				// Put /skydns/nipe-systems/foo/x1
				switch t := record.(type) {
				case *dns.A:
					path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					data, sha, err := a.recordAToJSONAndPathSuffix(t)
					if err != nil {
						fmt.Println("error:", err)
					}
					path = path + "/" + sha

					leaseID, err := a.updateEtcdLease(path)
					if err != nil {
						log.Print(err)
					}

					log.Printf("  Put %s = %s", path, data)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Put(ctx, path, string(data), clientv3.WithLease(leaseID))
					cancel()
					if err != nil {
						log.Print(err)
					}
					if resp.PrevKv != nil {
						log.Printf("  Successfully overwritten key in etcd (previous: %s)", resp.PrevKv.Value)
					} else {
						log.Printf("  Successfully put key in etcd")
					}
				case *dns.TXT:
					path := domainNameToPath([]string{"skydns"}, t.Hdr.Name)
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					data, sha, err := a.recordTXTToJSONAndPathSuffix(t)
					if err != nil {
						fmt.Println("error:", err)
					}
					path = path + "/" + sha

					leaseID, err := a.updateEtcdLease(path)
					if err != nil {
						log.Print(err)
					}

					log.Printf("  Put %s = %s", path, data)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Put(ctx, path, string(data), clientv3.WithLease(leaseID))
					cancel()
					if err != nil {
						log.Print(err)
					}
					if resp.PrevKv != nil {
						log.Printf("  Successfully overwritten key in etcd (previous: %s)", resp.PrevKv.Value)
					} else {
						log.Printf("  Successfully put key in etcd")
					}
				default:
					log.Printf("  Type %T not implemented", t)
				}
			}
		}
	}
	m := new(dns.Msg)
	m.SetReply(r)
	w.WriteMsg(m)
}

func main() {
	var config adaptorConfig

	app := cli.NewApp()
	app.Name = "rfc2136-skydns-etcd-adaptor"
	app.Usage = "Adapts RFC2136 (DNS UPDATE) to SkyDNS/etcd for CoreDNS usage"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "dns-listen-addr, l",
			Usage:       "Listen address for DNS server",
			Value:       ":53",
			Destination: &config.dnsListenAddr,
			EnvVar:      "ADAPTOR_DNS_LISTEN_ADDR",
		},
		cli.StringFlag{
			Name:        "dns-listen-proto, p",
			Usage:       "DNS proto to listen on",
			Destination: &config.dnsListenProto,
			Value:       "udp",
			EnvVar:      "ADAPTOR_DNS_LISTEN_PROTO",
		},
		cli.StringFlag{
			Name:        "etcd-dial-addr, a",
			Value:       "localhost:2379",
			Usage:       "Dial address to connect to etcd",
			Destination: &config.etcdDialAddr,
			EnvVar:      "ADAPTOR_ETCD_DIAL_ADDR",
		},
		cli.StringFlag{
			Name:        "etcd-lease-ttl, t",
			Value:       "300",
			Usage:       "Lease Time-to-live for individual keys (auto cleanup of keys)",
			Destination: &config.etcdLeaseTTL,
			EnvVar:      "ADAPTOR_ETCD_LEASE_TTL",
		},
		cli.StringFlag{
			Name:        "addr-mapping, m",
			Value:       "{}",
			Usage:       "Address mapping in JSON: if a key address is matched the value address is used instead",
			Destination: &config.addrMapping,
			EnvVar:      "ADAPTOR_ADDR_MAPPING",
		},
	}

	app.Action = func(_ *cli.Context) error {
		log.Printf("Config: %+v", config)

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

		a, err := newAdaptor(config)
		if err != nil {
			log.Fatal(err)
		}
		defer a.shutdown()

		select {
		case s := <-c:
			log.Printf("Got signal %v, exiting.", s)
		case err := <-a.errorCh:
			log.Fatal(err)
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
