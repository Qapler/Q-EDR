// Package network defines network telemetry data types.
package network

// ConnectData contains the payload for network.connect events.
type ConnectData struct {
	Family     string `json:"family"`      // "ipv4", "ipv6", "unix"
	Protocol   string `json:"protocol"`    // "tcp", "udp", "unix_stream", "unix_dgram"
	Direction  string `json:"direction"`   // "outbound"
	LocalAddr  string `json:"local_addr,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	RetCode    int32  `json:"ret_code,omitempty"`
	SocketFD   int32  `json:"socket_fd,omitempty"`
}

// AcceptData contains the payload for network.accept events.
type AcceptData struct {
	Family     string `json:"family"`
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction"` // "inbound"
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	NewFD      int32  `json:"new_fd,omitempty"`
}

// BindData contains the payload for network.bind events.
type BindData struct {
	Family   string `json:"family"`
	Protocol string `json:"protocol"`
	Addr     string `json:"addr"`
	Port     uint16 `json:"port"`
	RetCode  int32  `json:"ret_code,omitempty"`
	SocketFD int32  `json:"socket_fd,omitempty"`
}

// ListenData contains the payload for network.listen events.
type ListenData struct {
	Family   string `json:"family"`
	Protocol string `json:"protocol"`
	Backlog  int32  `json:"backlog"`
	SocketFD int32  `json:"socket_fd,omitempty"`
}

// CloseData contains the payload for network.close events.
type CloseData struct {
	Family     string `json:"family"`
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	OldState   string `json:"old_state,omitempty"`
	NewState   string `json:"new_state"`
	BytesSent  uint64 `json:"bytes_sent,omitempty"`
	BytesRecv  uint64 `json:"bytes_recv,omitempty"`
}

// SocketSnapshotData contains the payload for network.snapshot events.
type SocketSnapshotData struct {
	Family     string `json:"family"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	Inode      uint64 `json:"inode,omitempty"`
	TxQueue    uint64 `json:"tx_queue,omitempty"`
	RxQueue    uint64 `json:"rx_queue,omitempty"`
}
