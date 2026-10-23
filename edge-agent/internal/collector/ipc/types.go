// Package ipc defines IPC telemetry data types.
package ipc

// PipeCreateData contains the payload for ipc.pipe_create events.
type PipeCreateData struct {
	ReadFD  int32 `json:"read_fd"`
	WriteFD int32 `json:"write_fd"`
	Flags   int32 `json:"flags,omitempty"`
	RetCode int32 `json:"ret_code,omitempty"`
}

// SocketPairData contains the payload for ipc.socketpair_create events.
type SocketPairData struct {
	Family   string `json:"family"`   // "unix"
	Type     string `json:"type"`     // "stream", "dgram", "seqpacket"
	Protocol int32  `json:"protocol"`
	FD0      int32  `json:"fd0"`
	FD1      int32  `json:"fd1"`
	RetCode  int32  `json:"ret_code,omitempty"`
}

// ShmGetData contains the payload for ipc.shm_get events.
type ShmGetData struct {
	Key     int32  `json:"key"`
	ShmID   int32  `json:"shm_id"`
	Size    uint64 `json:"size"`
	ShmFlg  int32  `json:"shm_flg"`
	FlagDesc string `json:"flag_desc,omitempty"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// ShmAttachData contains the payload for ipc.shm_attach events.
type ShmAttachData struct {
	ShmID   int32  `json:"shm_id"`
	ShmAddr uint64 `json:"shm_addr,omitempty"` // Requested address (0 = kernel chooses).
	ShmFlg  int32  `json:"shm_flg"`
}

// MsgGetData contains the payload for ipc.msg_get events.
type MsgGetData struct {
	Key     int32  `json:"key"`
	MsgID   int32  `json:"msg_id"`
	MsgFlg  int32  `json:"msg_flg"`
	FlagDesc string `json:"flag_desc,omitempty"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// MsgSendData contains the payload for ipc.msg_send events.
type MsgSendData struct {
	MsgID   int32  `json:"msg_id"`
	MsgType int64  `json:"msg_type"`
	MsgSize uint64 `json:"msg_size"`
	MsgFlg  int32  `json:"msg_flg"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// MsgReceiveData contains the payload for ipc.msg_receive events.
type MsgReceiveData struct {
	MsgID      int32  `json:"msg_id"`
	MsgType    int64  `json:"msg_type"`
	MsgSize    uint64 `json:"msg_size"`
	MsgFlg     int32  `json:"msg_flg"`
	RetCode    int32  `json:"ret_code,omitempty"`
}

// SemGetData contains the payload for ipc.sem_get events.
type SemGetData struct {
	Key     int32  `json:"key"`
	SemID   int32  `json:"sem_id"`
	NSems   int32  `json:"nsems"`
	SemFlg  int32  `json:"sem_flg"`
	FlagDesc string `json:"flag_desc,omitempty"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// SemOpData contains the payload for ipc.sem_op events.
type SemOpData struct {
	SemID    int32 `json:"sem_id"`
	NSops    int32 `json:"nsops"`
	RetCode  int32 `json:"ret_code,omitempty"`
}

// IPCSnapshotData contains the payload for ipc.snapshot events.
type IPCSnapshotData struct {
	ResourceType string `json:"resource_type"` // "shm", "msg", "sem"
	Key          int32  `json:"key"`
	ID           int32  `json:"id"`
	OwnerUID     uint32 `json:"owner_uid"`
	Permissions  uint32 `json:"permissions"`
	Size         uint64 `json:"size,omitempty"`
	LastOpTime   int64  `json:"last_op_time,omitempty"`
	NumAttach    int32  `json:"num_attach,omitempty"` // SHM only.
}
