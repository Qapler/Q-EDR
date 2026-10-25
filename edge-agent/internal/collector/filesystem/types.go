// Package filesystem defines filesystem telemetry data types.
package filesystem

// OpenData contains the payload for filesystem.open events.
type OpenData struct {
	Path      string `json:"path,omitempty"`
	PathError string `json:"path_error,omitempty"` // When path resolution fails.
	Flags     int32  `json:"flags"`
	FlagsDesc string `json:"flags_desc,omitempty"` // Human-readable flags.
	Mode      uint32 `json:"mode,omitempty"`
	FD        int32  `json:"fd,omitempty"`
	RetCode   int32  `json:"ret_code,omitempty"`
	DirFD     int32  `json:"dir_fd,omitempty"` // AT_FDCWD or directory FD.
	Inode     uint64 `json:"inode,omitempty"`
	Device    uint64 `json:"device,omitempty"`
}

// CreateData is used when filesystem.open includes O_CREAT (aliases to filesystem.create).
type CreateData = OpenData

// WriteData contains the payload for filesystem.write events.
type WriteData struct {
	FD       int32  `json:"fd"`
	Path     string `json:"path,omitempty"`
	Count    uint64 `json:"count"`       // Requested bytes.
	Written  int64  `json:"written"`     // Actually written bytes (-1 on error).
	RetCode  int32  `json:"ret_code,omitempty"`
	Inode    uint64 `json:"inode,omitempty"`
	Device   uint64 `json:"device,omitempty"`
}

// RenameData contains the payload for filesystem.rename events.
type RenameData struct {
	OldPath   string `json:"old_path,omitempty"`
	NewPath   string `json:"new_path,omitempty"`
	OldDirFD  int32  `json:"old_dir_fd,omitempty"`
	NewDirFD  int32  `json:"new_dir_fd,omitempty"`
	Flags     int32  `json:"flags,omitempty"`
	RetCode   int32  `json:"ret_code,omitempty"`
}

// UnlinkData contains the payload for filesystem.unlink events.
type UnlinkData struct {
	Path     string `json:"path,omitempty"`
	DirFD    int32  `json:"dir_fd,omitempty"`
	Flags    int32  `json:"flags,omitempty"`
	IsDir    bool   `json:"is_dir"` // True when AT_REMOVEDIR is set (rmdir).
	RetCode  int32  `json:"ret_code,omitempty"`
}

// MkdirData contains the payload for filesystem.mkdir events.
type MkdirData struct {
	Path    string `json:"path,omitempty"`
	DirFD   int32  `json:"dir_fd,omitempty"`
	Mode    uint32 `json:"mode"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// ChmodData contains the payload for filesystem.chmod events.
type ChmodData struct {
	Path    string `json:"path,omitempty"`
	DirFD   int32  `json:"dir_fd,omitempty"`
	Mode    uint32 `json:"mode"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// ChownData contains the payload for filesystem.chown events.
type ChownData struct {
	Path    string `json:"path,omitempty"`
	DirFD   int32  `json:"dir_fd,omitempty"`
	OwnerID int32  `json:"owner_id"`
	GroupID int32  `json:"group_id"`
	RetCode int32  `json:"ret_code,omitempty"`
}

// MountSnapshotData contains the payload for filesystem.snapshot events.
type MountSnapshotData struct {
	Device     string `json:"device"`
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	Options    string `json:"options,omitempty"`
}
