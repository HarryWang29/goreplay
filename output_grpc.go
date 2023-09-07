package goreplay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/buger/goreplay/api/passive"
	cmap "github.com/orcaman/concurrent-map/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type GrpcOutput struct {
	address string
	limit   int
	config  *GrpcOutputConfig
	stream  passive.PassiveService_PassiveStreamClient
	m       cmap.ConcurrentMap[string, *RR]

	sendCount int64
	recvCount int64
}

type GrpcOutputConfig struct {
	ErrWait    time.Duration `json:"err_wait"`
	AgentID    string        `json:"agent_id"`
	Token      string        `json:"token"`
	PassiveID  uint32        `json:"passive_id"`
	PassiveIDu uint          `json:"passive_id_u"`
	TicketTime time.Duration `json:"ticket_time"`
}

type RR struct {
	flow    *passive.Flow
	reqT    time.Time
	rspT    time.Time
	req     *http.Request
	rsp     *http.Response
	reqBody []byte
	rspBody []byte
}

func (o *GrpcOutput) Start() error {
	var err error
	var conn *grpc.ClientConn
	keepAliveParams := keepalive.ClientParameters{
		Time:    5 * time.Second,
		Timeout: 10 * time.Second,
	}
	//grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stdout, os.Stdout, os.Stderr))
	//grpc.EnableTracing = true
	for {
		ctx := context.Background()
		conn, err = grpc.DialContext(ctx, o.address,
			// grpc.WithStreamInterceptor(rpc.StreamInterceptor),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithKeepaliveParams(keepAliveParams),
		)
		if err != nil {
			log.Printf("dial failed! will retry after 30s. err:%v", err)
			time.Sleep(o.config.ErrWait)
			continue
		}

		client := passive.NewPassiveServiceClient(conn)
		stream, err := client.PassiveStream(ctx)
		o.stream = stream
		if err != nil {
			log.Printf("client create duplex stream err:%v", err)
			time.Sleep(o.config.ErrWait)
			conn.Close()
			continue
		}
		log.Printf("PassiveWorker-[%d] connect Agent-[%s] success", o.config.PassiveID, o.config.AgentID)
		err = stream.Send(&passive.UpMessage{
			PassiveID: o.config.PassiveID,
			Msg: &passive.UpMessage_AuthMsg{
				AuthMsg: &passive.AuthMsg{
					Token: o.config.Token,
					State: passive.PassiveState_Running,
				},
			},
		})
		if err != nil {
			log.Printf("register failed err:%v", err)
			time.Sleep(o.config.ErrWait)
			conn.Close()
			continue
		}
		log.Printf("PassiveWorker-[%d] register to Agent-[%s] success", o.config.PassiveID, o.config.AgentID)

		for {
			_, err := stream.Recv()
			if err == io.EOF {
				log.Printf("target Agent unlink connect")
				// w.state.Store(0)
				// log.Errorf("Passive-Worker stopped on err:%v", err)
				break
			}
			if err != nil {
				log.Printf("receive data err:%v", err)
				// w.state.Store(0)
				// log.Errorf("Passive-Worker stopped on err:%v", err)
				break
			}
		}
		conn.Close()
	}
}

func NewGrpcOutput(address string, config *GrpcOutputConfig) PluginWriter {
	o := new(GrpcOutput)
	o.m = cmap.New[*RR]()
	config.PassiveID = uint32(config.PassiveIDu)
	o.config = config
	o.address = address

	go o.Start()
	go o.work()
	return o
}

func (o *GrpcOutput) work() {
	ticker := time.Tick(o.config.TicketTime)
	for {
		select {
		case <-ticker:
			if o.stream == nil {
				time.Sleep(o.config.ErrWait)
				continue
			}
			mm := o.m
			o.m = cmap.New[*RR]()
			ss := make([]*passive.HTTPSession, 0, 100)
			ks := make([]string, 0, 100)
			krm := make(map[string]*RR)
			mm.IterCb(func(key string, rr *RR) {
				var req *passive.ApiAnalyzeRequest
				var rsp *passive.ApiAnalyzeResponse
				if rr.req != nil {
					reqhdr := []byte{}
					if rr.req.Header != nil && len(rr.req.Header) > 0 {
						xss := []string{}
						for k, vs := range rr.req.Header {
							x := strings.Join(vs, " ")
							xs := fmt.Sprintf("%s:%s", k, x)
							xss = append(xss, xs)
						}
						reqhdr = []byte(strings.Join(xss, "\n"))
					}
					req = &passive.ApiAnalyzeRequest{
						Time:   rr.reqT.UnixMilli(),
						Method: passive.HTTPMethod(passive.HTTPMethod_value[rr.req.Method]),
						Uri:    []byte(rr.req.RequestURI),
						Host:   []byte(rr.req.Host),
						Verion: []byte(rr.req.Proto),
						Body:   rr.reqBody,
						Header: reqhdr,
					}
				}
				if rr.rsp != nil {
					rsphdr := []byte{}
					if rr.rsp.Header != nil && len(rr.rsp.Header) > 0 {
						xss := []string{}
						for k, vs := range rr.rsp.Header {
							x := strings.Join(vs, " ")
							xs := fmt.Sprintf("%s:%s", k, x)
							xss = append(xss, xs)
						}
						rsphdr = []byte(strings.Join(xss, "\n"))
					}
					rsp = &passive.ApiAnalyzeResponse{
						Time:       rr.rspT.UnixMilli(),
						StatusCode: uint32(rr.rsp.StatusCode),
						Verion:     []byte(rr.rsp.Proto),
						Header:     rsphdr,
						Body:       rr.rspBody,
					}
				}
				s := &passive.HTTPSession{
					Flow: rr.flow,
					Rr: []*passive.HTTPRR{
						{
							Req: req,
							Rsp: rsp,
						},
					},
				}
				ss = append(ss, s)
				ks = append(ks, key)
				krm[key] = rr
				if len(ss) >= 100 {
					err := o.SendMsg(ss)
					if err != nil {
						log.Printf("send data err:%v", err)
						for _, v := range ks {
							if vv, ok := krm[v]; ok {
								o.m.Set(v, vv)
							}
						}
					} else {
						o.sendCount += int64(len(ss))
						ss = make([]*passive.HTTPSession, 0, 100)
						ks = make([]string, 0, 100)
						krm = make(map[string]*RR)
					}
				}
			})
			if len(ss) > 0 {
				err := o.SendMsg(ss)
				if err != nil {
					log.Printf("send data err:%v", err)
					for _, v := range ks {
						if vv, ok := krm[v]; ok {
							o.m.Set(v, vv)
						}
					}
				} else {
					o.sendCount += int64(len(ss))
					ss = make([]*passive.HTTPSession, 0, 100)
					ks = make([]string, 0, 100)
					krm = make(map[string]*RR)
				}
			}
			log.Printf("sendCount:%d, recvCount:%d", o.sendCount, o.recvCount)
		}
	}
}

func (o *GrpcOutput) SendMsg(ss []*passive.HTTPSession) error {
	return o.stream.Send(&passive.UpMessage{
		PassiveID: o.config.PassiveID,
		Msg: &passive.UpMessage_HttpMsg{
			HttpMsg: &passive.HTTPMsg{
				Session: ss,
			},
		},
	})
}

func (o *GrpcOutput) PluginWrite(msg *Message) (int, error) {
	o.recvCount++
	meta := payloadMeta(msg.Meta)
	if len(meta) < 3 {
		log.Printf("meta len err: %d", len(meta))
		return 0, nil
	}
	tiNano, _ := strconv.ParseInt(string(meta[2]), 10, 64)
	seconds := tiNano / int64(time.Second)
	nanoseconds := tiNano % int64(time.Second)
	ts := time.Unix(seconds, nanoseconds)
	data := bytes.NewReader(msg.Data)
	buf := bufio.NewReader(data)
	sip, dip, sport, dport := DecodeUUID(meta[1])
	flow := &passive.Flow{
		Sip:   net.IP(sip).String(),
		Dip:   net.IP(dip).String(),
		Sport: uint32(sport),
		Dport: uint32(dport),
	}

	if isRequestPayload(msg.Meta) {
		var rr *RR
		var ok bool
		if rr, ok = o.m.Get(string(meta[1])); !ok {
			rr = &RR{
				flow: flow,
			}
		}
		req, err := http.ReadRequest(buf)
		if err != nil {
			log.Printf("read request err:%s id: %s", err, string(meta[1]))
			return 0, nil
		}
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		rr.req = req
		rr.reqT = ts
		rr.flow = flow
		rr.reqBody = body
		o.m.Set(string(meta[1]), rr)
	} else {
		var rr *RR
		var ok bool
		if rr, ok = o.m.Get(string(meta[1])); !ok {
			rr = &RR{
				flow: flow,
			}
		}
		readResponse, err := http.ReadResponse(buf, rr.req)
		if err != nil {
			log.Printf("read response err:%s id:%s", err, string(meta[1]))
			return 0, nil
		}
		rr.rspT = ts
		rr.rsp = readResponse
		body, _ := io.ReadAll(readResponse.Body)
		_ = readResponse.Body.Close()
		rr.rspBody = body
		o.m.Set(string(meta[1]), rr)
	}
	return len(msg.Data) + len(msg.Meta), nil
}

func DecodeUUID(uuid []byte) (sip []byte, dip []byte, sport uint16, dport uint16) {
	dst := make([]byte, 16)
	hex.Decode(dst[:], uuid)
	srcport := dst[0:2]
	dstport := dst[2:4]
	sip = dst[4:8]
	dip = dst[8:12]
	sport = binary.BigEndian.Uint16(srcport)
	dport = binary.BigEndian.Uint16(dstport)
	return
}

func (o *GrpcOutput) String() string {
	return "Grpc Output"
}
