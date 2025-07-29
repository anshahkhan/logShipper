package internal

import (
	"net"
)

func SendToServer(ip, port string, data []byte) error {
	address := net.JoinHostPort(ip, port)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(data)
	return err
}
