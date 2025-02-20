package cmd

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Expose Warp as a SOCKS5 proxy",
	Long:  "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		bindAddress, err := cmd.Flags().GetString("bind")
		if err != nil {
			cmd.Printf("Failed to get bind address: %v\n", err)
			return
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			cmd.Printf("Failed to get port: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		var endpoint *net.UDPAddr
		if ipv6, err := cmd.Flags().GetBool("ipv6"); err == nil && !ipv6 {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV4),
				Port: connectPort,
			}
		} else {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV6),
				Port: connectPort,
			}
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		var username string
		var password string
		if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
			username = u
		}
		if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
			password = p
		}

		log.Printf("Establishing MASQUE connection to %s:%d (%s)", endpoint.IP, endpoint.Port, sni)

		udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(
			context.Background(),
			tlsConfig,
			internal.DefaultQuicConfig(keepalivePeriod, initialPacketSize),
			internal.ConnectURI,
			endpoint,
		)
		if err != nil {
			cmd.Printf("Failed to connect tunnel: %v\n", err)
			return
		}
		if tr != nil {
			defer tr.Close()
		}
		if udpConn != nil {
			defer udpConn.Close()
		}
		defer ipConn.Close()

		if rsp.StatusCode != 200 {
			cmd.Printf("Failed to connect tunnel: %s\n", rsp.Status)
			return
		}

		log.Println("Connected to MASQUE server, creating virtual tunnel")

		time.Sleep(500 * time.Millisecond)

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer tunDev.Close()

		go func() {
			packetBufs := make([][]byte, 1)
			for i := range packetBufs {
				packetBufs[i] = make([]byte, mtu)
			}
			sizes := make([]int, 1)

			for {
				_, err := tunDev.Read(packetBufs, sizes, 0)
				if err != nil {
					log.Fatalf("failed to read from TUN device: %v\n", err)
				}

				icmp, err := ipConn.WritePacket(packetBufs[0][:sizes[0]])
				if err != nil {
					log.Fatalf("failed to write to IP connection: %v\n", err)
				}
				if len(icmp) > 0 {
					if _, err := tunDev.Write([][]byte{icmp}, 0); err != nil {
						log.Fatalf("failed to write ICMP to TUN device: %v\n", err)
					}
				}
			}
		}()

		go func() {
			for {
				b := make([]byte, mtu)
				n, err := ipConn.ReadPacket(b, true)
				if err != nil {
					log.Fatalf("failed to read from IP connection: %v", err)
				}

				_, err = tunDev.Write([][]byte{b[:n]}, 0)
				if err != nil {
					log.Fatalf("failed to write to TUN device: %v", err)
				}
			}
		}()

		var server *socks5.Server
		if username == "" || password == "" {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tunNet.DialContext(ctx, network, addr)
				}),
			)
		} else {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tunNet.DialContext(ctx, network, addr)
				}),
				socks5.WithAuthMethods(
					[]socks5.Authenticator{
						socks5.UserPassAuthenticator{
							Credentials: socks5.StaticCredentials{
								username: password,
							},
						},
					},
				),
			)
		}

		log.Printf("SOCKS proxy listening on %s:%s", bindAddress, port)
		if err := server.ListenAndServe("tcp", net.JoinHostPort(bindAddress, port)); err != nil {
			cmd.Printf("Failed to start SOCKS proxy: %v\n", err)
			return
		}
	},
}

func init() {
	socksCmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size for MASQUE connection")
	rootCmd.AddCommand(socksCmd)
}
