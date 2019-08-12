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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
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
	etcdClient *clientv3.Client
	dnsServer  *dns.Server
	errorCh    <-chan error
}

func newAdaptor() (*adaptor, error) {
	dnsServer := &dns.Server{Addr: ":5353", Net: "udp", MsgAcceptFunc: msgAcceptFunc}

	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to etcd %s", etcdClient.ActiveConnection().Target())

	errorCh := make(chan error, 1)

	a := &adaptor{
		etcdClient: etcdClient,
		dnsServer:  dnsServer,
		errorCh:    errorCh,
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

func (a *adaptor) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
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
						nameParts := dns.SplitDomainName(t.Hdr.Name)
						sort.Sort(sort.Reverse(sort.StringSlice(nameParts)))
						path := "/" + strings.Join(append([]string{"skydns"}, nameParts...), "/")
						log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						resp, err := a.etcdClient.Delete(ctx, path, clientv3.WithPrefix())
						cancel()
						if err != nil {
							log.Print(err)
						}
						log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)
					default:
						log.Printf("  Type %T not implemented", t)
					}
				} else {
					// delete an RRset
					log.Printf("  Delete an RRset ...")
					// Del /skydns/nipe-systems/foo
					switch t := record.(type) {
					case *dns.A:
						nameParts := dns.SplitDomainName(t.Hdr.Name)
						sort.Sort(sort.Reverse(sort.StringSlice(nameParts)))
						path := "/" + strings.Join(append([]string{"skydns"}, nameParts...), "/")
						log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						resp, err := a.etcdClient.Delete(ctx, path, clientv3.WithPrefix())
						cancel()
						if err != nil {
							log.Print(err)
						}
						log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)
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
					nameParts := dns.SplitDomainName(t.Hdr.Name)
					sort.Sort(sort.Reverse(sort.StringSlice(nameParts)))
					path := "/" + strings.Join(append([]string{"skydns"}, nameParts...), "/")
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					type etcdValue struct {
						Host string `json:"host"`
						TTL  uint32 `json:"ttl,omitempty"`
					}
					data, err := json.Marshal(etcdValue{t.A.String(), t.Hdr.Ttl})
					if err != nil {
						fmt.Println("error:", err)
					}
					hasher := sha1.New()
					hasher.Write(data)
					sha := hex.EncodeToString(hasher.Sum(nil))
					path = path + "/" + sha

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Delete(ctx, path)
					cancel()
					if err != nil {
						log.Print(err)
					}
					log.Printf("  Successfully deleted %d keys from etcd", resp.Deleted)
				default:
					log.Printf("  Type %T not implemented", t)
				}
			} else {
				// add to an RRset
				log.Printf("  Add to an RRset")
				// Put /skydns/nipe-systems/foo/x1
				switch t := record.(type) {
				case *dns.A:
					nameParts := dns.SplitDomainName(t.Hdr.Name)
					sort.Sort(sort.Reverse(sort.StringSlice(nameParts)))
					path := "/" + strings.Join(append([]string{"skydns"}, nameParts...), "/")
					log.Printf("  Path: %s -> %s", t.Hdr.Name, path)

					type etcdValue struct {
						Host string `json:"host"`
						TTL  uint32 `json:"ttl,omitempty"`
					}
					data, err := json.Marshal(etcdValue{t.A.String(), t.Hdr.Ttl})
					if err != nil {
						fmt.Println("error:", err)
					}
					hasher := sha1.New()
					hasher.Write(data)
					sha := hex.EncodeToString(hasher.Sum(nil))
					path = path + "/" + sha

					log.Printf("  Put %s = %s", path, data)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					resp, err := a.etcdClient.Put(ctx, path, string(data))
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
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	a, err := newAdaptor()
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
}