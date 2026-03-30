package logic

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"golang.org/x/crypto/ssh"
)

type ShellType string

const (
	ShellTypeNormal ShellType = "shell"
	ShellTypeUndead ShellType = "undead"
	ShellTypeWorm   ShellType = "worm"
	ShellTypeMD5    ShellType = "md5"
)

type ProgressEvent struct {
	TaskID  string `json:"taskId"`
	Current int64  `json:"current"`
	Total   int64  `json:"total"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type CommandResult struct {
	Target  string `json:"target"`
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Message string `json:"message"`
}

type TaskState struct {
	TaskID      string          `json:"taskId"`
	Status      string          `json:"status"`
	Current     int64           `json:"current"`
	Total       int64           `json:"total"`
	Message     string          `json:"message"`
	StartedAt   time.Time       `json:"startedAt"`
	FinishedAt  *time.Time      `json:"finishedAt,omitempty"`
	Results     []CommandResult `json:"results,omitempty"`
	LastError   string          `json:"lastError,omitempty"`
	LastUpdated time.Time       `json:"lastUpdated"`
}

type AttackService struct {
	client *req.Client
	tasks  sync.Map
}

type DefenseService struct {
	knownHosts map[string]string
	mu         sync.RWMutex
	sshService *ServiceService
}

type DetectionService struct {
	AliveHosts []string
	ExistHosts map[string]struct{}
	livewg     sync.WaitGroup
	mu         sync.RWMutex
}

type MonitorService struct {
	stopChan      chan bool
	captureMu     sync.RWMutex
	captureCtx    context.Context
	captureCancel context.CancelFunc
	captureStart  time.Time
	captureIface  string
	captureFilter string
	captureSeq    uint64
	captureLive   bool
	captureStop   map[string]func()
	captureHosts  map[string]map[string]struct{}
	captureRows   []RemoteTrafficRecord
	captureHTTP   map[string]*liveHTTPStream
	sessions      map[string]*RemoteCaptureSession
	sshService    *ServiceService
}

type FlagService struct {
	client    *req.Client
	attackSvc *AttackService
}

type FileMonitor struct {
	Path         string    `json:"path"`
	LastModified time.Time `json:"lastModified"`
	Size         int64     `json:"size"`
	Hash         string    `json:"hash"`
}

type ShellFinding struct {
	Target string `json:"target"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type SSHPasswordChangeParams struct {
	TargetsInput   string   `json:"targetsInput"`
	Username       string   `json:"username"`
	Port           string   `json:"port"`
	OldPasswords   []string `json:"oldPasswords"`
	NewPassword    string   `json:"newPassword"`
	MaxConcurrency int64    `json:"maxConcurrency"`
}

type SSHPasswordChangeResult struct {
	IP           string `json:"ip"`
	UsedPassword string `json:"usedPassword"`
	Status       string `json:"status"`
	Message      string `json:"message"`
}

type SSHPasswordChangeResponse struct {
	Results    []SSHPasswordChangeResult `json:"results"`
	Total      int64                     `json:"total"`
	Success    int64                     `json:"success"`
	AuthFailed int64                     `json:"authFailed"`
	Timeout    int64                     `json:"timeout"`
	Error      int64                     `json:"error"`
}

type FlagResult struct {
	Target  string `json:"target"`
	Flag    string `json:"flag"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type SmokeCheckResult struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

type SmokeProgressEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Stage     string    `json:"stage"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
	Line      string    `json:"line"`
}

type SmokeReport struct {
	Results    []SmokeCheckResult   `json:"results"`
	Progress   []SmokeProgressEvent `json:"progress"`
	StartedAt  time.Time            `json:"startedAt"`
	FinishedAt time.Time            `json:"finishedAt"`
	DurationMS int64                `json:"durationMs"`
	Passed     int                  `json:"passed"`
	Failed     int                  `json:"failed"`
	Status     string               `json:"status"`
	Error      string               `json:"error,omitempty"`
}

type RemoteCaptureRequest struct {
	TargetsInput string `json:"targetsInput"`
	Interface    string `json:"interface"`
	Filter       string `json:"filter"`
}

type RemoteCaptureSession struct {
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	StartedAt time.Time `json:"startedAt"`
	LastSeen  time.Time `json:"lastSeen"`
	LastLine  string    `json:"lastLine"`
	Error     string    `json:"error,omitempty"`
}

type RemoteTrafficRecord struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"`
	Protocol  string    `json:"protocol"`
	SrcIP     string    `json:"srcIp"`
	DstIP     string    `json:"dstIp"`
	SrcPort   string    `json:"srcPort"`
	DstPort   string    `json:"dstPort"`
	Summary   string    `json:"summary"`
	Raw       string    `json:"raw"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Status    string    `json:"status,omitempty"`
}

type RemoteCaptureState struct {
	Running   bool                   `json:"running"`
	Interface string                 `json:"interface"`
	Filter    string                 `json:"filter"`
	StartedAt time.Time              `json:"startedAt"`
	Sessions  []RemoteCaptureSession `json:"sessions"`
	Records   []RemoteTrafficRecord  `json:"records"`
}

type RemoteCaptureEvent struct {
	Kind    string                `json:"kind"`
	Message string                `json:"message"`
	Session *RemoteCaptureSession `json:"session,omitempty"`
	Record  *RemoteTrafficRecord  `json:"record,omitempty"`
	State   *RemoteCaptureState   `json:"state,omitempty"`
}

type liveHTTPStream struct {
	Summary  string
	Body     string
	Method   string
	Path     string
	Status   string
	LastSeen time.Time
}

type ServiceService struct {
	mu              sync.RWMutex
	latestSmoke     *SmokeReport
	sshClient       *ssh.Client
	sshRequest      SSHConnectRequest
	sshConnectedAt  time.Time
	sshLastError    string
	terminalMu      sync.Mutex
	terminalSession *ssh.Session
	terminalInput   io.WriteCloser
	terminalActive  bool
}

type SSHConnectRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type SSHConnectionState struct {
	Connected    bool      `json:"connected"`
	Host         string    `json:"host"`
	Port         string    `json:"port"`
	Username     string    `json:"username"`
	ConnectedAt  time.Time `json:"connectedAt"`
	LastError    string    `json:"lastError"`
	TerminalOpen bool      `json:"terminalOpen"`
}

type TerminalOutputEvent struct {
	Kind      string    `json:"kind"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

type RemoteFileEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"isDir"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
}

type RemoteFileList struct {
	CurrentPath string            `json:"currentPath"`
	ParentPath  string            `json:"parentPath"`
	Entries     []RemoteFileEntry `json:"entries"`
}

type FileTransferResult struct {
	Name       string `json:"name"`
	RemotePath string `json:"remotePath"`
	LocalPath  string `json:"localPath"`
	Size       int64  `json:"size"`
}
