// Package ntpcore provides core NTP protocol structures and utilities
// based on RFC 5905 (NTPv4) and RFC 4330 (SNTPv4)
package ntpcore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// NTP timestamp epoch: January 1, 1900 00:00:00 UTC
// Unix epoch: January 1, 1970 00:00:00 UTC
// Difference: 70 years (including 17 leap years)
const (
	NTPEpochOffset = 2208988800 // Seconds between NTP and Unix epochs

	// NTP packet size
	NTPPacketSize    = 48
	NTPPacketMinSize = 48
	NTPPacketMaxSize = 68 // With optional authentication

	// Leap Indicator values
	LeapNoWarning     = 0 // No warning
	LeapLastMinute61  = 1 // Last minute of day has 61 seconds
	LeapLastMinute59  = 2 // Last minute of day has 59 seconds
	LeapAlarm         = 3 // Alarm condition (clock not synchronized)

	// Mode values
	ModeReserved         = 0
	ModeSymmetricActive  = 1
	ModeSymmetricPassive = 2
	ModeClient           = 3
	ModeServer           = 4
	ModeBroadcast        = 5
	ModeControl          = 6
	ModePrivate          = 7

	// Version values
	VersionNTPv3 = 3
	VersionNTPv4 = 4

	// Kiss-of-Death codes (ASCII in Reference ID)
	KoDACSTDeny    = "ACST" // The association belongs to a anycast server
	KoDAuthFail    = "AUTH" // Server authentication failed
	KoDAuto        = "AUTO" // Autokey sequence failed
	KoDBcst        = "BCST" // The association belongs to a broadcast server
	KoDCryp        = "CRYP" // Cryptographic authentication or identification failed
	KoDDeny        = "DENY" // Access denied by remote server
	KoDDrop        = "DROP" // Lost peer in symmetric mode
	KoDRstr        = "RSTR" // Access denied due to local policy
	KoDInit        = "INIT" // The association has not yet synchronized for the first time
	KoDMcst        = "MCST" // The association belongs to a dynamically discovered server
	KoDNkey        = "NKEY" // No key found
	KoDRate        = "RATE" // Rate exceeded
	KoDRmot        = "RMOT" // Alteration of association from a remote host running ntpdc
	KoDStep        = "STEP" // A step change in system time has occurred
)

// NTPPacket represents an NTP packet as defined in RFC 5905
type NTPPacket struct {
	// First byte: LI (2 bits) | VN (3 bits) | Mode (3 bits)
	LeapIndicator uint8 // 2 bits
	Version       uint8 // 3 bits
	Mode          uint8 // 3 bits

	Stratum      uint8  // Stratum level (0-15)
	Poll         int8   // Poll interval (log2 seconds)
	Precision    int8   // Clock precision (log2 seconds)
	RootDelay    uint32 // Root delay (NTP short format)
	RootDisp     uint32 // Root dispersion (NTP short format)
	ReferenceID  uint32 // Reference ID (IP address or kiss code)
	RefTimeSec   uint32 // Reference timestamp (seconds)
	RefTimeFrac  uint32 // Reference timestamp (fraction)
	OrigTimeSec  uint32 // Origin timestamp (seconds)
	OrigTimeFrac uint32 // Origin timestamp (fraction)
	RecvTimeSec  uint32 // Receive timestamp (seconds)
	RecvTimeFrac uint32 // Receive timestamp (fraction)
	XmitTimeSec  uint32 // Transmit timestamp (seconds)
	XmitTimeFrac uint32 // Transmit timestamp (fraction)
}

// NTPTimestamp represents an NTP timestamp (64 bits)
type NTPTimestamp struct {
	Seconds  uint32
	Fraction uint32
}

// TimeToNTPTimestamp converts a Go time.Time to NTP timestamp
func TimeToNTPTimestamp(t time.Time) NTPTimestamp {
	// Get Unix timestamp
	secs := t.Unix() + NTPEpochOffset
	
	// Calculate fraction (nanoseconds to NTP fraction)
	// NTP fraction is 2^32 / 10^9 of nanosecond
	nanos := t.Nanosecond()
	frac := uint32((float64(nanos) / 1e9) * float64(1<<32))
	
	return NTPTimestamp{
		Seconds:  uint32(secs),
		Fraction: frac,
	}
}

// NTPTimestampToTime converts an NTP timestamp to Go time.Time
func NTPTimestampToTime(ts NTPTimestamp) time.Time {
	secs := int64(ts.Seconds) - NTPEpochOffset
	nanos := int64((float64(ts.Fraction) / float64(1<<32)) * 1e9)
	return time.Unix(secs, nanos)
}

// NewPacket creates a new NTP packet with default values
func NewPacket() *NTPPacket {
	return &NTPPacket{
		LeapIndicator: LeapNoWarning,
		Version:       VersionNTPv4,
		Mode:          ModeServer,
		Stratum:       2,
		Poll:          6,         // 64 seconds
		Precision:     -20,       // ~1 microsecond
		RootDelay:     0,
		RootDisp:      0,
		ReferenceID:   0,
	}
}

// ParsePacket parses a byte slice into an NTPPacket
func ParsePacket(data []byte) (*NTPPacket, error) {
	if len(data) < NTPPacketMinSize {
		return nil, errors.New("packet too short")
	}

	p := &NTPPacket{}
	
	// Parse first byte
	firstByte := data[0]
	p.LeapIndicator = (firstByte >> 6) & 0x03
	p.Version = (firstByte >> 3) & 0x07
	p.Mode = firstByte & 0x07

	p.Stratum = data[1]
	p.Poll = int8(data[2])
	p.Precision = int8(data[3])
	p.RootDelay = binary.BigEndian.Uint32(data[4:8])
	p.RootDisp = binary.BigEndian.Uint32(data[8:12])
	p.ReferenceID = binary.BigEndian.Uint32(data[12:16])
	p.RefTimeSec = binary.BigEndian.Uint32(data[16:20])
	p.RefTimeFrac = binary.BigEndian.Uint32(data[20:24])
	p.OrigTimeSec = binary.BigEndian.Uint32(data[24:28])
	p.OrigTimeFrac = binary.BigEndian.Uint32(data[28:32])
	p.RecvTimeSec = binary.BigEndian.Uint32(data[32:36])
	p.RecvTimeFrac = binary.BigEndian.Uint32(data[36:40])
	p.XmitTimeSec = binary.BigEndian.Uint32(data[40:44])
	p.XmitTimeFrac = binary.BigEndian.Uint32(data[44:48])

	return p, nil
}

// Bytes serializes the NTPPacket to bytes
func (p *NTPPacket) Bytes() []byte {
	data := make([]byte, NTPPacketSize)

	// First byte: LI | VN | Mode
	data[0] = (p.LeapIndicator << 6) | (p.Version << 3) | p.Mode
	data[1] = p.Stratum
	data[2] = byte(p.Poll)
	data[3] = byte(p.Precision)
	binary.BigEndian.PutUint32(data[4:8], p.RootDelay)
	binary.BigEndian.PutUint32(data[8:12], p.RootDisp)
	binary.BigEndian.PutUint32(data[12:16], p.ReferenceID)
	binary.BigEndian.PutUint32(data[16:20], p.RefTimeSec)
	binary.BigEndian.PutUint32(data[20:24], p.RefTimeFrac)
	binary.BigEndian.PutUint32(data[24:28], p.OrigTimeSec)
	binary.BigEndian.PutUint32(data[28:32], p.OrigTimeFrac)
	binary.BigEndian.PutUint32(data[32:36], p.RecvTimeSec)
	binary.BigEndian.PutUint32(data[36:40], p.RecvTimeFrac)
	binary.BigEndian.PutUint32(data[40:44], p.XmitTimeSec)
	binary.BigEndian.PutUint32(data[44:48], p.XmitTimeFrac)

	return data
}

// SetReferenceTime sets the reference timestamp
func (p *NTPPacket) SetReferenceTime(t time.Time) {
	ts := TimeToNTPTimestamp(t)
	p.RefTimeSec = ts.Seconds
	p.RefTimeFrac = ts.Fraction
}

// SetOriginTime sets the origin timestamp (copy from client's transmit)
func (p *NTPPacket) SetOriginTime(sec, frac uint32) {
	p.OrigTimeSec = sec
	p.OrigTimeFrac = frac
}

// SetReceiveTime sets the receive timestamp
func (p *NTPPacket) SetReceiveTime(t time.Time) {
	ts := TimeToNTPTimestamp(t)
	p.RecvTimeSec = ts.Seconds
	p.RecvTimeFrac = ts.Fraction
}

// SetTransmitTime sets the transmit timestamp
func (p *NTPPacket) SetTransmitTime(t time.Time) {
	ts := TimeToNTPTimestamp(t)
	p.XmitTimeSec = ts.Seconds
	p.XmitTimeFrac = ts.Fraction
}

// GetTransmitTime returns the transmit time as time.Time
func (p *NTPPacket) GetTransmitTime() time.Time {
	return NTPTimestampToTime(NTPTimestamp{
		Seconds:  p.XmitTimeSec,
		Fraction: p.XmitTimeFrac,
	})
}

// SetKissOfDeathCode sets the reference ID to a kiss code
func (p *NTPPacket) SetKissOfDeathCode(code string) error {
	if len(code) != 4 {
		return errors.New("kiss code must be exactly 4 characters")
	}
	p.Stratum = 0 // KoD packets have stratum 0
	p.ReferenceID = binary.BigEndian.Uint32([]byte(code))
	return nil
}

// GetKissOfDeathCode returns the kiss code if stratum is 0
func (p *NTPPacket) GetKissOfDeathCode() string {
	if p.Stratum != 0 {
		return ""
	}
	code := make([]byte, 4)
	binary.BigEndian.PutUint32(code, p.ReferenceID)
	return string(code)
}

// SetReferenceIDFromIP sets the reference ID from an IP address string
func (p *NTPPacket) SetReferenceIDFromIP(ip string) {
	// Parse IP and convert to uint32
	var parts [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3])
	p.ReferenceID = binary.BigEndian.Uint32(parts[:])
}

// GetModeString returns a human-readable mode string
func (p *NTPPacket) GetModeString() string {
	switch p.Mode {
	case ModeReserved:
		return "Reserved"
	case ModeSymmetricActive:
		return "Symmetric Active"
	case ModeSymmetricPassive:
		return "Symmetric Passive"
	case ModeClient:
		return "Client"
	case ModeServer:
		return "Server"
	case ModeBroadcast:
		return "Broadcast"
	case ModeControl:
		return "Control"
	case ModePrivate:
		return "Private"
	default:
		return "Unknown"
	}
}

// IsValidClientRequest checks if the packet is a valid client request
func (p *NTPPacket) IsValidClientRequest() bool {
	return p.Mode == ModeClient && (p.Version == VersionNTPv3 || p.Version == VersionNTPv4)
}

// String returns a human-readable representation of the packet
func (p *NTPPacket) String() string {
	return fmt.Sprintf("NTP{LI:%d VN:%d Mode:%s Stratum:%d Poll:%d Prec:%d}",
		p.LeapIndicator, p.Version, p.GetModeString(), p.Stratum, p.Poll, p.Precision)
}

// CalculateRootDelay converts milliseconds to NTP short format
func CalculateRootDelay(ms float64) uint32 {
	// NTP short format: 16 bits seconds, 16 bits fraction
	secs := ms / 1000.0
	return uint32(secs * 65536)
}

// CalculateRootDispersion converts milliseconds to NTP short format
func CalculateRootDispersion(ms float64) uint32 {
	return CalculateRootDelay(ms)
}
