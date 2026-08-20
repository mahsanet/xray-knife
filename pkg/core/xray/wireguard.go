package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/GFW-knocker/Xray-core/infra/conf"
)

// parseReserved converts a WireGuard "reserved" link value into bytes.
// Accepts a comma-separated list of ints (e.g. "1,2,3", as used by WARP) or
// a base64 string. Returns nil when it can't parse.
func parseReserved(s string) []byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		b := make([]byte, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > 255 {
				return nil
			}
			b = append(b, byte(n))
		}
		return b
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return dec
	}
	if dec, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return dec
	}
	return nil
}

func NewWireguard(link string) Protocol {
	return &Wireguard{OrigLink: link}
}

func (w *Wireguard) Name() string {
	return "wireguard"
}

func (w *Wireguard) Parse() error {
	if !strings.HasPrefix(w.OrigLink, protocol.WireguardIdentifier) {
		return fmt.Errorf("wireguard unreconized: %s", w.OrigLink)
	}

	uri, err := url.Parse(w.OrigLink)
	if err != nil {
		return err
	}

	unescapedSecretKey, err0 := url.PathUnescape(uri.User.String())
	if err0 != nil {
		return err0
	}

	w.SecretKey = unescapedSecretKey

	w.Endpoint = uri.Host

	// Get the type of the struct
	t := reflect.TypeOf(*w)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(w).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int32":
				var intValue int
				fmt.Sscanf(value, "%d", &intValue)
				v.SetInt(int64(intValue))

			}
		}
	}

	w.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		w.Remark = uri.Fragment
	}

	return nil
}

func (w *Wireguard) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), w.Name(),
		color.RedString("Remark"), w.Remark,
		color.RedString("Endpoint"), w.Endpoint,
		color.RedString("MTU"), w.Mtu,
		color.RedString("Local Addresses"), w.LocalAddress,
		color.RedString("Public Key"), w.PublicKey,
		color.RedString("Secret Key"), w.SecretKey,
	)

	return info
}

// GetLink generates a WireGuard config link from the struct's fields.
func (w *Wireguard) GetLink() string {
	if w.OrigLink != "" {
		return w.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "wireguard",
			User:   url.User(w.SecretKey),
			Host:   w.Endpoint,
		}

		params := url.Values{}
		addQueryParam := func(key, value string) {
			if value != "" {
				params.Add(key, value)
			}
		}
		addQueryParamInt := func(key string, value int32) {
			if value != 0 {
				params.Add(key, strconv.FormatInt(int64(value), 10))
			}
		}

		addQueryParam("publickey", w.PublicKey)
		addQueryParam("presharedkey", w.PreSharedKey)
		addQueryParam("address", w.LocalAddress)
		addQueryParamInt("mtu", w.Mtu)
		addQueryParamInt("keepalive", w.KeepAlive)
		addQueryParam("allowedips", w.AllowedIPs)
		addQueryParam("reserved", w.Reserved)

		baseURL.RawQuery = params.Encode()

		if w.Remark != "" {
			baseURL.Fragment = w.Remark
		}

		return baseURL.String()
	}
}

func (w *Wireguard) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = w.Name()
	g.Address = w.Endpoint
	g.OrigLink = w.GetLink()

	return g
}

type Peer struct {
	Endpoint     string   `json:"endpoint"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	KeepAlive    uint32   `json:"keepAlive,omitempty"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

type Config struct {
	SecretKey string   `json:"secretKey"`
	Address   []string `json:"address"`
	Peers     []Peer   `json:"peers"`
	MTU       int      `json:"mtu"`
	Reserved  []byte   `json:"reserved,omitempty"`
}

func (w *Wireguard) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	out := &conf.OutboundDetourConfig{}
	out.Tag = "proxy"
	out.Protocol = w.Name()

	//c := conf.WireGuardConfig{
	//	IsClient:   true,
	//	KernelMode: nil,
	//	SecretKey:  w.SecretKey,
	//	Address:    strings.Split(w.LocalAddress, ","),
	//	Peers: []*conf.WireGuardPeerConfig{
	//		{
	//			PublicKey:    w.PublicKey,
	//			PreSharedKey: "",
	//			Endpoint:     w.Endpoint,
	//			KeepAlive:    0,
	//			AllowedIPs:   nil,
	//		},
	//	},
	//	MTU:            w.Mtu,
	//	DomainStrategy: "ForceIPv6v4",
	//}

	//oset := json.RawMessage(fmt.Sprintf({
	//	"secretKey": "%s",
	//		"address": ["%s", "%s"],
	//"peers": [
	//{
	//"endpoint": "%s",
	//"publicKey": "%s"
	//}
	//],
	//"mtu": %d
	//}
	//, w.SecretKey, strings.Split(w.LocalAddress, ",")[0], strings.Split(w.LocalAddress, ",")[1], w.Endpoint, w.PublicKey, w.Mtu,
	//))

	// Prepare the address slice safely.
	addresses := strings.Split(w.LocalAddress, ",")

	peer := Peer{
		Endpoint:     w.Endpoint,
		PublicKey:    w.PublicKey,
		PreSharedKey: w.PreSharedKey,
	}
	if w.KeepAlive > 0 {
		peer.KeepAlive = uint32(w.KeepAlive)
	}
	if w.AllowedIPs != "" {
		var ips []string
		for _, ip := range strings.Split(w.AllowedIPs, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ips = append(ips, ip)
			}
		}
		peer.AllowedIPs = ips
	}

	cfg := Config{
		SecretKey: w.SecretKey,
		Address:   addresses,
		Peers:     []Peer{peer},
		MTU:       int(w.Mtu),
	}
	if r := parseReserved(w.Reserved); len(r) > 0 {
		cfg.Reserved = r
	}

	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
		// handle error
	}

	//out.Settings = &oset
	rawMSG := json.RawMessage(jsonData)
	out.Settings = &rawMSG

	return out, nil
}

func (w *Wireguard) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, fmt.Errorf("creating a WireGuard inbound from a client link is not supported")
}
